using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Lidgren.Network
{
	public partial class NetPeer
	{
		/*
		 * Fragmentation security limits.
		 *
		 * IMPORTANT:
		 * These limits exist because all fragmentation header values are
		 * controlled by the remote peer and MUST NOT be trusted before
		 * allocating memory.
		 *
		 * For SS14 these limits are intentionally very generous for legitimate
		 * traffic while preventing a single peer from requesting absurd
		 * allocations.
		 */

		// Maximum reconstructed size of ONE fragmented message.
		// Increase this only if you have confirmed legitimate messages larger
		// than this.
		private const int MaxFragmentedMessageBytes = 16 * 1024 * 1024; // 16 MiB

		// Prevents pathological NetBitVector allocations and messages split into
		// an unreasonable number of tiny fragments.
		private const int MaxFragmentChunks = 32768;

		// Maximum number of unfinished fragmented messages per connection.
		private const int MaxFragmentGroupsPerConnection = 8;

		// Maximum memory occupied by unfinished fragments from one connection.
		private const long MaxBufferedFragmentBytesPerConnection =
			32L * 1024 * 1024; // 32 MiB

		// Maximum memory occupied by unfinished fragments across this NetPeer.
		private const long MaxBufferedFragmentBytesTotal =
			128L * 1024 * 1024; // 128 MiB

		private int m_lastUsedFragmentGroup;

		private readonly Dictionary<NetConnection, Dictionary<int, ReceivedFragmentGroup>>
			m_receivedFragmentGroups;

		/*
		 * ReceivedFragmentGroup itself only stores Data + ReceivedChunks.
		 *
		 * Keep the immutable shape of the first fragment separately so an
		 * attacker cannot start a group with one chunk size and continue the
		 * same group using different fragmentation metadata.
		 *
		 * ConditionalWeakTable is used so this metadata cannot keep completed
		 * or disconnected fragment groups alive by itself.
		 */
		private readonly ConditionalWeakTable<ReceivedFragmentGroup, FragmentGroupMetadata>
			m_fragmentGroupMetadata = new();

		private sealed class FragmentGroupMetadata
		{
			public readonly int TotalBits;
			public readonly int TotalBytes;
			public readonly int ChunkByteSize;
			public readonly int TotalChunks;

			public FragmentGroupMetadata(
				int totalBits,
				int totalBytes,
				int chunkByteSize,
				int totalChunks)
			{
				TotalBits = totalBits;
				TotalBytes = totalBytes;
				ChunkByteSize = chunkByteSize;
				TotalChunks = totalChunks;
			}
		}

		// on user thread
		private NetSendResult SendFragmentedMessage(
			NetOutgoingMessage msg,
			IList<NetConnection> recipients,
			NetDeliveryMethod method,
			int sequenceChannel)
		{
			int group = Interlocked.Increment(ref m_lastUsedFragmentGroup);

			if (group >= NetConstants.MaxFragmentationGroups)
			{
				// Existing Lidgren behaviour.
				// Technically this assignment is not perfectly thread-safe,
				// but changing the group allocator is outside the scope of
				// the receive-side security fix.
				m_lastUsedFragmentGroup = 1;
				group = 1;
			}

			msg.m_fragmentGroup = group;

			// Do not send msg itself; mark it fragmented in case the user tries
			// to recycle it immediately.
			int totalBytes = msg.LengthBytes;

			if (totalBytes <= 0)
				throw new InvalidOperationException(
					"Cannot fragment an empty network message.");

			/*
			 * m_fragmentGroupTotalBits is an Int32.
			 * Prevent integer overflow on totalBytes * 8.
			 */
			if (totalBytes > int.MaxValue / 8)
				throw new InvalidOperationException(
					"Network message is too large to represent as a fragmented message.");

			int mtu = GetMTU(recipients);

			int bytesPerChunk =
				NetFragmentationHelper.GetBestChunkSize(group, totalBytes, mtu);

			if (bytesPerChunk <= 0)
				throw new InvalidOperationException(
					"Calculated fragment chunk size is invalid.");

			int numChunks = totalBytes / bytesPerChunk;

			if (numChunks * bytesPerChunk < totalBytes)
				numChunks++;

			if (numChunks <= 0)
				throw new InvalidOperationException(
					"Calculated fragment count is invalid.");

			NetSendResult retval = NetSendResult.Sent;

			int bitsPerChunk = checked(bytesPerChunk * 8);
			int bitsLeft = msg.LengthBits;

			for (int i = 0; i < numChunks; i++)
			{
				NetOutgoingMessage chunk = CreateMessage(0);

				chunk.m_bitLength =
					bitsLeft > bitsPerChunk
						? bitsPerChunk
						: bitsLeft;

				chunk.m_data = msg.m_data;
				chunk.m_fragmentGroup = group;
				chunk.m_fragmentGroupTotalBits = totalBytes * 8;
				chunk.m_fragmentChunkByteSize = bytesPerChunk;
				chunk.m_fragmentChunkNumber = i;

				NetException.Assert(chunk.m_bitLength != 0);
				NetException.Assert(chunk.GetEncodedSize() < mtu);

				Interlocked.Add(
					ref chunk.m_recyclingCount,
					recipients.Count);

				foreach (NetConnection recipient in recipients)
				{
					var res = recipient.EnqueueMessage(
						chunk,
						method,
						sequenceChannel);

					if (res == NetSendResult.Dropped)
						Interlocked.Decrement(
							ref chunk.m_recyclingCount);

					if ((int) res > (int) retval)
						retval = res;
				}

				bitsLeft -= bitsPerChunk;
			}

			return retval;
		}

		private void HandleReleasedFragment(NetIncomingMessage im)
		{
			VerifyNetworkThread();

			/*
			 * Never trust ANY field from the fragmentation header.
			 *
			 * In particular:
			 *   totalBits
			 *   chunkByteSize
			 *   chunkNumber
			 *   group
			 *
			 * all originate from the remote peer.
			 */

			int ptr;
			int group;
			int totalBits;
			int chunkByteSize;
			int chunkNumber;

			try
			{
				ptr = NetFragmentationHelper.ReadHeader(
					im.Data,
					0,
					out group,
					out totalBits,
					out chunkByteSize,
					out chunkNumber);
			}
			catch (Exception)
			{
				RejectFragment(
					im,
					"Invalid fragmentation header");

				return;
			}

			/*
			 * Header must end before the end of the packet.
			 * An empty fragment payload is never valid here.
			 */
			if (ptr < 0 || ptr >= im.LengthBytes)
			{
				RejectFragment(
					im,
					"Invalid fragmentation header length");

				return;
			}

			if (group <= 0 ||
			    group >= NetConstants.MaxFragmentationGroups)
			{
				RejectFragment(
					im,
					"Invalid fragmentation group");

				return;
			}

			if (totalBits <= 0)
			{
				RejectFragment(
					im,
					"Invalid fragmented message bit length");

				return;
			}

			if (chunkByteSize <= 0)
			{
				RejectFragment(
					im,
					"Invalid fragment chunk size");

				return;
			}

			if (chunkNumber < 0)
			{
				RejectFragment(
					im,
					"Invalid fragment chunk number");

				return;
			}

			/*
			 * Do all size arithmetic using long first.
			 *
			 * DO NOT call BytesToHoldBits(totalBits) and immediately allocate
			 * from it before applying a limit.
			 */
			long totalBytesLong =
				((long) totalBits + 7L) / 8L;

			if (totalBytesLong <= 0 ||
			    totalBytesLong > MaxFragmentedMessageBytes)
			{
				RejectFragment(
					im,
					"Fragmented message exceeds maximum allowed size");

				return;
			}

			/*
			 * ceil(totalBytes / chunkByteSize), avoiding multiplication
			 * overflow.
			 */
			long totalNumChunksLong =
				(totalBytesLong + chunkByteSize - 1L) /
				chunkByteSize;

			if (totalNumChunksLong <= 0 ||
			    totalNumChunksLong > MaxFragmentChunks ||
			    totalNumChunksLong > int.MaxValue)
			{
				RejectFragment(
					im,
					"Invalid or excessive fragment count");

				return;
			}

			int totalBytes = (int) totalBytesLong;
			int totalNumChunks = (int) totalNumChunksLong;

			if (chunkNumber >= totalNumChunks)
			{
				RejectFragment(
					im,
					"Fragment index is outside the fragment group");

				return;
			}

			/*
			 * Validate the actual payload against the declared fragmentation
			 * layout BEFORE doing Buffer.BlockCopy.
			 */
			int fragmentPayloadBytes =
				im.LengthBytes - ptr;

			if (fragmentPayloadBytes <= 0)
			{
				RejectFragment(
					im,
					"Fragment contains no payload");

				return;
			}

			long offsetLong =
				(long) chunkNumber * chunkByteSize;

			if (offsetLong < 0 ||
			    offsetLong >= totalBytesLong)
			{
				RejectFragment(
					im,
					"Fragment destination offset is invalid");

				return;
			}

			long remainingBytes =
				totalBytesLong - offsetLong;

			long expectedPayloadBytes =
				Math.Min(
					(long) chunkByteSize,
					remainingBytes);

			/*
			 * Normal Lidgren fragmentation produces exactly chunkByteSize
			 * bytes for every non-final chunk and exactly the remaining
			 * bytes for the final chunk.
			 *
			 * Requiring an exact match prevents inconsistent layouts,
			 * overlaps and truncated chunks.
			 */
			if (fragmentPayloadBytes != expectedPayloadBytes)
			{
				RejectFragment(
					im,
					"Fragment payload size does not match header");

				return;
			}

			long copyEndLong =
				offsetLong + fragmentPayloadBytes;

			if (copyEndLong < offsetLong ||
			    copyEndLong > totalBytesLong)
			{
				RejectFragment(
					im,
					"Fragment copy would exceed destination buffer");

				return;
			}

			NetConnection? sender = im.SenderConnection;

			if (sender == null)
			{
				RejectFragment(
					im,
					"Fragment has no sender connection");

				return;
			}

			if (!m_receivedFragmentGroups.TryGetValue(
				    sender,
				    out Dictionary<int, ReceivedFragmentGroup>? groups))
			{
				groups =
					new Dictionary<int, ReceivedFragmentGroup>();

				m_receivedFragmentGroups[sender] = groups;
			}

			if (!groups.TryGetValue(
				    group,
				    out ReceivedFragmentGroup? info))
			{
				/*
				 * Limit the number of independent allocations an individual
				 * connection can hold open.
				 */
				if (groups.Count >= MaxFragmentGroupsPerConnection)
				{
					RejectFragment(
						im,
						"Too many unfinished fragment groups");

					return;
				}

				long connectionBufferedBytes =
					GetBufferedFragmentBytes(groups);

				if (connectionBufferedBytes >
				    MaxBufferedFragmentBytesPerConnection -
				    totalBytesLong)
				{
					RejectFragment(
						im,
						"Per-connection fragment memory budget exceeded");

					return;
				}

				long totalBufferedBytes =
					GetTotalBufferedFragmentBytes();

				if (totalBufferedBytes >
				    MaxBufferedFragmentBytesTotal -
				    totalBytesLong)
				{
					RejectFragment(
						im,
						"Global fragment memory budget exceeded");

					return;
				}

				/*
				 * This is the security-critical allocation.
				 *
				 * At this point:
				 *
				 * - totalBytes is positive
				 * - totalBytes <= MaxFragmentedMessageBytes
				 * - chunk count is bounded
				 * - per-connection memory is bounded
				 * - global fragment memory is bounded
				 */
				try
				{
					info = new ReceivedFragmentGroup(
						new byte[totalBytes],
						new NetBitVector(totalNumChunks));
				}
				catch (OutOfMemoryException)
				{
					/*
					 * Bounds above should make attacker-controlled OOMs here
					 * impossible under normal operating conditions.
					 *
					 * This catch is only a last-resort guard if the process is
					 * already genuinely low on memory.
					 */
					RejectFragmentWithoutLogging(im);
					return;
				}

				groups[group] = info;

				m_fragmentGroupMetadata.Add(
					info,
					new FragmentGroupMetadata(
						totalBits,
						totalBytes,
						chunkByteSize,
						totalNumChunks));
			}
			else
			{
				/*
				 * A group is immutable after its first fragment.
				 *
				 * Without this check, a remote peer could reuse the same group
				 * ID while changing totalBits/chunkByteSize between packets.
				 */
				if (info.Data.Length != totalBytes ||
				    info.ReceivedChunks.Capacity != totalNumChunks)
				{
					RemoveFragmentGroup(
						sender,
						groups,
						group,
						info);

					RejectFragment(
						im,
						"Fragment group dimensions changed");

					return;
				}

				if (!m_fragmentGroupMetadata.TryGetValue(
					    info,
					    out FragmentGroupMetadata? metadata))
				{
					/*
					 * Should not normally happen, but reconstruct the
					 * metadata rather than trusting a changed subsequent
					 * packet.
					 */
					metadata = new FragmentGroupMetadata(
						totalBits,
						totalBytes,
						chunkByteSize,
						totalNumChunks);

					m_fragmentGroupMetadata.Add(
						info,
						metadata);
				}

				if (metadata.TotalBits != totalBits ||
				    metadata.TotalBytes != totalBytes ||
				    metadata.ChunkByteSize != chunkByteSize ||
				    metadata.TotalChunks != totalNumChunks)
				{
					RemoveFragmentGroup(
						sender,
						groups,
						group,
						info);

					RejectFragment(
						im,
						"Fragment group metadata changed");

					return;
				}
			}

			/*
			 * At this point Capacity was checked both when the group was
			 * created and when an existing group was retrieved.
			 */
			if (chunkNumber >= info.ReceivedChunks.Capacity)
			{
				RemoveFragmentGroup(
					sender,
					groups,
					group,
					info);

				RejectFragment(
					im,
					"Fragment index exceeds receive bitmap");

				return;
			}

			/*
			 * Duplicate fragment.
			 *
			 * Do not repeatedly BlockCopy identical chunk numbers. Apart from
			 * being unnecessary, dropping duplicates cheaply reduces CPU work
			 * under packet spam.
			 */
			if (info.ReceivedChunks[chunkNumber])
			{
				Recycle(im);
				return;
			}

			int offset = (int) offsetLong;

			/*
			 * Final defensive check immediately before the copy.
			 */
			if (offset < 0 ||
			    offset > info.Data.Length ||
			    fragmentPayloadBytes >
			    info.Data.Length - offset)
			{
				RemoveFragmentGroup(
					sender,
					groups,
					group,
					info);

				RejectFragment(
					im,
					"Fragment copy bounds are invalid");

				return;
			}

			Buffer.BlockCopy(
				im.Data,
				ptr,
				info.Data,
				offset,
				fragmentPayloadBytes);

			/*
			 * Mark the chunk received AFTER a successful copy.
			 *
			 * If BlockCopy ever failed, we must not consider the chunk
			 * complete.
			 */
			info.ReceivedChunks[chunkNumber] = true;

			int receivedCount =
				info.ReceivedChunks.Count();

			LogVerbose(
				$"Received fragment {chunkNumber} of {totalNumChunks} " +
				$"({receivedCount} chunks received)");

			if (receivedCount == totalNumChunks)
			{
				/*
				 * Completed message.
				 *
				 * Transfer the reconstructed storage to the incoming message
				 * before dropping our fragment-group references.
				 */
				im.m_data = info.Data;
				im.m_bitLength = totalBits;
				im.m_isFragment = false;

				LogVerbose(
					$"Fragment group #{group} fully received in " +
					$"{totalNumChunks} chunks ({totalBits} bits)");

				RemoveFragmentGroup(
					sender,
					groups,
					group,
					info);

				ReleaseMessage(im);
				return;
			}

			// Fragment data has been copied into info.Data.
			Recycle(im);
		}

		/// <summary>
		/// Returns the amount of fragment payload memory currently held for a
		/// single connection.
		/// </summary>
		private static long GetBufferedFragmentBytes(
			Dictionary<int, ReceivedFragmentGroup> groups)
		{
			long total = 0;

			foreach (ReceivedFragmentGroup group in groups.Values)
			{
				if (group.Data == null)
					continue;

				/*
				 * Saturate instead of overflowing the accounting variable.
				 */
				if (total > long.MaxValue - group.Data.LongLength)
					return long.MaxValue;

				total += group.Data.LongLength;
			}

			return total;
		}

		/// <summary>
		/// Returns the amount of fragment payload memory currently retained by
		/// this peer across all connections.
		/// </summary>
		private long GetTotalBufferedFragmentBytes()
		{
			long total = 0;

			foreach (Dictionary<int, ReceivedFragmentGroup> groups
			         in m_receivedFragmentGroups.Values)
			{
				long connectionBytes =
					GetBufferedFragmentBytes(groups);

				if (connectionBytes == long.MaxValue)
					return long.MaxValue;

				if (total > long.MaxValue - connectionBytes)
					return long.MaxValue;

				total += connectionBytes;
			}

			return total;
		}

		private void RemoveFragmentGroup(
			NetConnection sender,
			Dictionary<int, ReceivedFragmentGroup> groups,
			int group,
			ReceivedFragmentGroup info)
		{
			groups.Remove(group);
			m_fragmentGroupMetadata.Remove(info);

			/*
			 * Do not retain an empty dictionary or NetConnection reference.
			 */
			if (groups.Count == 0)
				m_receivedFragmentGroups.Remove(sender);
		}

		/// <summary>
		/// Drops a malformed fragment and disconnects the associated peer.
		///
		/// Do not include raw packet contents in the log.
		/// </summary>
		private void RejectFragment(
			NetIncomingMessage im,
			string reason)
		{
			NetConnection? sender = im.SenderConnection;

			if (sender != null)
			{
				LogWarning(
					$"Dropping malformed fragmented message from " +
					$"{sender.RemoteEndPoint}: {reason}");

				/*
				 * A malformed fragmentation header is a protocol violation.
				 * Do not allow the connection to continue feeding the
				 * reassembly path.
				 */
				sender.Disconnect(
					"Malformed fragmented network message");
			}

			Recycle(im);
		}

		/// <summary>
		/// OOM fallback which deliberately avoids formatting/logging strings.
		///
		/// If the process is genuinely out of memory, even diagnostic logging
		/// can itself allocate.
		/// </summary>
		private void RejectFragmentWithoutLogging(
			NetIncomingMessage im)
		{
			NetConnection? sender = im.SenderConnection;

			try
			{
				sender?.Disconnect(
					"Fragment allocation failed");
			}
			catch
			{
				// Do not let cleanup code make an OOM situation worse.
			}

			try
			{
				Recycle(im);
			}
			catch
			{
				// Same reasoning as above.
			}
		}
	}
}
