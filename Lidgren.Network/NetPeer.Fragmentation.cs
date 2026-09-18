using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Lidgren.Network
{
	public partial class NetPeer
	{
		private const int MaxFragmentedMessageBytes = 16 * 1024 * 1024;
		private const int MaxFragmentChunks = 32768;
		private const int MaxFragmentGroupsPerConnection = 8;
		private const long MaxBufferedFragmentBytesPerConnection = 32L * 1024 * 1024;
		private const long MaxBufferedFragmentBytesTotal = 128L * 1024 * 1024;

		private int m_lastUsedFragmentGroup;

		private readonly Dictionary<NetConnection, Dictionary<int, ReceivedFragmentGroup>>
			m_receivedFragmentGroups = new();

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

		private NetSendResult SendFragmentedMessage(
			NetOutgoingMessage msg,
			IList<NetConnection> recipients,
			NetDeliveryMethod method,
			int sequenceChannel)
		{
			int group = Interlocked.Increment(ref m_lastUsedFragmentGroup);

			if (group >= NetConstants.MaxFragmentationGroups)
			{
				m_lastUsedFragmentGroup = 1;
				group = 1;
			}

			msg.m_fragmentGroup = group;

			int totalBytes = msg.LengthBytes;

			int mtu = GetMTU(recipients);

			int bytesPerChunk =
				NetFragmentationHelper.GetBestChunkSize(
					group,
					totalBytes,
					mtu);

			int numChunks = totalBytes / bytesPerChunk;

			if (numChunks * bytesPerChunk < totalBytes)
				numChunks++;

			NetSendResult retval = NetSendResult.Sent;

			int bitsPerChunk = bytesPerChunk * 8;
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

					if ((int)res > (int)retval)
						retval = res;
				}

				bitsLeft -= bitsPerChunk;
			}

			return retval;
		}

		private void HandleReleasedFragment(NetIncomingMessage im)
		{
			VerifyNetworkThread();

			if (!NetFragmentationHelper.TryReadHeader(
				    im.Data,
				    0,
				    im.LengthBytes,
				    out int ptr,
				    out int group,
				    out int totalBits,
				    out int chunkByteSize,
				    out int chunkNumber))
			{
				RejectFragment(im);
				return;
			}

			if (ptr < 0 || ptr >= im.LengthBytes)
			{
				RejectFragment(im);
				return;
			}

			if (group <= 0 ||
			    group >= NetConstants.MaxFragmentationGroups)
			{
				RejectFragment(im);
				return;
			}

			if (totalBits <= 0 ||
			    chunkByteSize <= 0 ||
			    chunkNumber < 0)
			{
				RejectFragment(im);
				return;
			}

			long totalBytesLong =
				((long)totalBits + 7L) / 8L;

			if (totalBytesLong <= 0 ||
			    totalBytesLong > MaxFragmentedMessageBytes)
			{
				RejectFragment(im);
				return;
			}

			long totalNumChunksLong =
				(totalBytesLong + chunkByteSize - 1L) /
				chunkByteSize;

			if (totalNumChunksLong <= 0 ||
			    totalNumChunksLong > MaxFragmentChunks ||
			    totalNumChunksLong > int.MaxValue)
			{
				RejectFragment(im);
				return;
			}

			int totalBytes = (int)totalBytesLong;
			int totalNumChunks = (int)totalNumChunksLong;

			if (chunkNumber >= totalNumChunks)
			{
				RejectFragment(im);
				return;
			}

			int fragmentPayloadBytes =
				im.LengthBytes - ptr;

			if (fragmentPayloadBytes <= 0)
			{
				RejectFragment(im);
				return;
			}

			long offsetLong =
				(long)chunkNumber * chunkByteSize;

			if (offsetLong < 0 ||
			    offsetLong >= totalBytesLong)
			{
				RejectFragment(im);
				return;
			}

			long remaining =
				totalBytesLong - offsetLong;

			long expectedPayloadBytes =
				Math.Min(
					(long)chunkByteSize,
					remaining);

			if (fragmentPayloadBytes != expectedPayloadBytes)
			{
				RejectFragment(im);
				return;
			}

			if (offsetLong + fragmentPayloadBytes >
			    totalBytesLong)
			{
				RejectFragment(im);
				return;
			}

			NetConnection? sender = im.SenderConnection;

			if (sender == null)
			{
				RejectFragment(im);
				return;
			}

			if (!m_receivedFragmentGroups.TryGetValue(
				    sender,
				    out var groups))
			{
				groups =
					new Dictionary<int, ReceivedFragmentGroup>();

				m_receivedFragmentGroups[sender] =
					groups;
			}

			if (!groups.TryGetValue(
				    group,
				    out var info))
			{
				if (groups.Count >=
				    MaxFragmentGroupsPerConnection)
				{
					RejectFragment(im);
					return;
				}

				long connectionBytes =
					GetBufferedFragmentBytes(groups);

				if (connectionBytes >
				    MaxBufferedFragmentBytesPerConnection -
				    totalBytesLong)
				{
					RejectFragment(im);
					return;
				}

				long globalBytes =
					GetTotalBufferedFragmentBytes();

				if (globalBytes >
				    MaxBufferedFragmentBytesTotal -
				    totalBytesLong)
				{
					RejectFragment(im);
					return;
				}

				try
				{
					info =
						new ReceivedFragmentGroup(
							new byte[totalBytes],
							new NetBitVector(totalNumChunks),
							totalBytes,
							totalBits,
							chunkByteSize,
							totalNumChunks,
							NetTime.Now);
				}
				catch (OutOfMemoryException)
				{
					RejectFragmentWithoutAllocations(im);
					return;
				}

				groups[group] =
					info;

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
				if (!m_fragmentGroupMetadata.TryGetValue(
					    info,
					    out var metadata))
				{
					RemoveFragmentGroup(
						sender,
						groups,
						group,
						info);

					RejectFragment(im);
					return;
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

					RejectFragment(im);
					return;
				}

				if (info.Data.Length != totalBytes)
				{
					RemoveFragmentGroup(
						sender,
						groups,
						group,
						info);

					RejectFragment(im);
					return;
				}
			}

			if (info.ReceivedChunks[chunkNumber])
			{
				Recycle(im);
				return;
			}

			int offset = (int)offsetLong;

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

				RejectFragment(im);
				return;
			}

			Buffer.BlockCopy(
				im.Data,
				ptr,
				info.Data,
				offset,
				fragmentPayloadBytes);

			info.ReceivedChunks[chunkNumber] = true;

			int receivedCount =
				info.ReceivedChunks.Count();

			LogVerbose(
				$"Received fragment {chunkNumber} of {totalNumChunks} ({receivedCount} chunks received)");

			if (receivedCount == totalNumChunks)
			{
				im.m_data = info.Data;
				im.m_bitLength = totalBits;
				im.m_isFragment = false;

				RemoveFragmentGroup(
					sender,
					groups,
					group,
					info);

				ReleaseMessage(im);
				return;
			}

			Recycle(im);
		}

		private static long GetBufferedFragmentBytes(
			Dictionary<int, ReceivedFragmentGroup> groups)
		{
			long total = 0;

			foreach (ReceivedFragmentGroup fragment
			         in groups.Values)
			{
				long length =
					fragment.Data.LongLength;

				if (total >
				    long.MaxValue - length)
				{
					return long.MaxValue;
				}

				total += length;
			}

			return total;
		}

		private long GetTotalBufferedFragmentBytes()
		{
			long total = 0;

			foreach (var groups
			         in m_receivedFragmentGroups.Values)
			{
				long connectionBytes =
					GetBufferedFragmentBytes(groups);

				if (connectionBytes == long.MaxValue)
					return long.MaxValue;

				if (total >
				    long.MaxValue - connectionBytes)
				{
					return long.MaxValue;
				}

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

			if (groups.Count == 0)
				m_receivedFragmentGroups.Remove(sender);
		}

		private void RejectFragment(
			NetIncomingMessage im)
		{
			var sender =
				im.SenderConnection;

			try
			{
				sender?.Disconnect(
					"Malformed fragmented network message");
			}
			finally
			{
				Recycle(im);
			}
		}

		private void RejectFragmentWithoutAllocations(
			NetIncomingMessage im)
		{
			try
			{
				im.SenderConnection?.Disconnect(
					"Malformed fragmented network message");
			}
			catch
			{
			}

			try
			{
				Recycle(im);
			}
			catch
			{
			}
		}
	}
}
