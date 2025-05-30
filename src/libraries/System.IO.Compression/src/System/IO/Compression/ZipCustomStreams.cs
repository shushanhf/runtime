// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace System.IO.Compression
{
    internal sealed class WrappedStream : Stream
    {
        private readonly Stream _baseStream;
        private readonly bool _closeBaseStream;

        // Delegate that will be invoked on stream disposing
        private readonly Action<ZipArchiveEntry?>? _onClosed;

        // Instance that will be passed to _onClose delegate
        private readonly ZipArchiveEntry? _zipArchiveEntry;
        private bool _isDisposed;

        internal WrappedStream(Stream baseStream, bool closeBaseStream)
            : this(baseStream, closeBaseStream, null, null) { }

        private WrappedStream(Stream baseStream, bool closeBaseStream, ZipArchiveEntry? entry, Action<ZipArchiveEntry?>? onClosed)
        {
            _baseStream = baseStream;
            _closeBaseStream = closeBaseStream;
            _onClosed = onClosed;
            _zipArchiveEntry = entry;
            _isDisposed = false;
        }

        internal WrappedStream(Stream baseStream, ZipArchiveEntry entry, Action<ZipArchiveEntry?>? onClosed)
            : this(baseStream, false, entry, onClosed) { }

        public override long Length
        {
            get
            {
                ThrowIfDisposed();
                return _baseStream.Length;
            }
        }

        public override long Position
        {
            get
            {
                ThrowIfDisposed();
                return _baseStream.Position;
            }
            set
            {
                ThrowIfDisposed();
                ThrowIfCantSeek();

                _baseStream.Position = value;
            }
        }

        public override bool CanRead => !_isDisposed && _baseStream.CanRead;

        public override bool CanSeek => !_isDisposed && _baseStream.CanSeek;

        public override bool CanWrite => !_isDisposed && _baseStream.CanWrite;

        private void ThrowIfDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().ToString(), SR.HiddenStreamName);
        }

        private void ThrowIfCantRead()
        {
            if (!CanRead)
                throw new NotSupportedException(SR.ReadingNotSupported);
        }

        private void ThrowIfCantWrite()
        {
            if (!CanWrite)
                throw new NotSupportedException(SR.WritingNotSupported);
        }

        private void ThrowIfCantSeek()
        {
            if (!CanSeek)
                throw new NotSupportedException(SR.SeekingNotSupported);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            ThrowIfCantRead();

            return _baseStream.Read(buffer, offset, count);
        }

        public override int Read(Span<byte> buffer)
        {
            ThrowIfDisposed();
            ThrowIfCantRead();

            return _baseStream.Read(buffer);
        }

        public override int ReadByte()
        {
            ThrowIfDisposed();
            ThrowIfCantRead();

            return _baseStream.ReadByte();
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            ThrowIfCantRead();

            return _baseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfCantRead();

            return _baseStream.ReadAsync(buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowIfDisposed();
            ThrowIfCantSeek();

            return _baseStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            ThrowIfDisposed();
            ThrowIfCantSeek();
            ThrowIfCantWrite();

            _baseStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            _baseStream.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> source)
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            _baseStream.Write(source);
        }

        public override void WriteByte(byte value)
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            _baseStream.WriteByte(value);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            return _baseStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            return _baseStream.WriteAsync(buffer, cancellationToken);
        }

        public override void Flush()
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            _baseStream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            ThrowIfCantWrite();

            return _baseStream.FlushAsync(cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_isDisposed)
            {
                _onClosed?.Invoke(_zipArchiveEntry);

                if (_closeBaseStream)
                    _baseStream.Dispose();

                _isDisposed = true;
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class SubReadStream : Stream
    {
        private readonly long _startInSuperStream;
        private long _positionInSuperStream;
        private readonly long _endInSuperStream;
        private readonly Stream _superStream;
        private bool _canRead;
        private bool _isDisposed;

        public SubReadStream(Stream superStream, long startPosition, long maxLength)
        {
            _startInSuperStream = startPosition;
            _positionInSuperStream = startPosition;
            _endInSuperStream = startPosition + maxLength;
            _superStream = superStream;
            _canRead = true;
            _isDisposed = false;
        }

        public override long Length
        {
            get
            {
                ThrowIfDisposed();

                return _endInSuperStream - _startInSuperStream;
            }
        }

        public override long Position
        {
            get
            {
                ThrowIfDisposed();

                return _positionInSuperStream - _startInSuperStream;
            }
            set
            {
                ThrowIfDisposed();

                throw new NotSupportedException(SR.SeekingNotSupported);
            }
        }

        public override bool CanRead => _superStream.CanRead && _canRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        private void ThrowIfDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().ToString(), SR.HiddenStreamName);
        }

        private void ThrowIfCantRead()
        {
            if (!CanRead)
                throw new NotSupportedException(SR.ReadingNotSupported);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // parameter validation sent to _superStream.Read
            int origCount = count;

            ThrowIfDisposed();
            ThrowIfCantRead();

            if (_superStream.Position != _positionInSuperStream)
                _superStream.Seek(_positionInSuperStream, SeekOrigin.Begin);
            if (_positionInSuperStream + count > _endInSuperStream)
                count = (int)(_endInSuperStream - _positionInSuperStream);

            Debug.Assert(count >= 0);
            Debug.Assert(count <= origCount);

            int ret = _superStream.Read(buffer, offset, count);

            _positionInSuperStream += ret;
            return ret;
        }

        public override int Read(Span<byte> destination)
        {
            // parameter validation sent to _superStream.Read
            int origCount = destination.Length;
            int count = destination.Length;

            ThrowIfDisposed();
            ThrowIfCantRead();

            if (_superStream.Position != _positionInSuperStream)
                _superStream.Seek(_positionInSuperStream, SeekOrigin.Begin);
            if (_positionInSuperStream + count > _endInSuperStream)
                count = (int)(_endInSuperStream - _positionInSuperStream);

            Debug.Assert(count >= 0);
            Debug.Assert(count <= origCount);

            int ret = _superStream.Read(destination.Slice(0, count));

            _positionInSuperStream += ret;
            return ret;
        }

        public override int ReadByte()
        {
            byte b = default;
            return Read(new Span<byte>(ref b)) == 1 ? b : -1;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBufferArguments(buffer, offset, count);
            return ReadAsync(new Memory<byte>(buffer, offset, count), cancellationToken).AsTask();
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfCantRead();
            return Core(buffer, cancellationToken);

            async ValueTask<int> Core(Memory<byte> buffer, CancellationToken cancellationToken)
            {
                if (_superStream.Position != _positionInSuperStream)
                {
                    _superStream.Seek(_positionInSuperStream, SeekOrigin.Begin);
                }

                if (_positionInSuperStream > _endInSuperStream - buffer.Length)
                {
                    buffer = buffer.Slice(0, (int)(_endInSuperStream - _positionInSuperStream));
                }

                int ret = await _superStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

                _positionInSuperStream += ret;
                return ret;
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.SeekingNotSupported);
        }

        public override void SetLength(long value)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.SetLengthRequiresSeekingAndWriting);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.WritingNotSupported);
        }

        public override void Flush()
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.WritingNotSupported);
        }

        // Close the stream for reading.  Note that this does NOT close the superStream (since
        // the substream is just 'a chunk' of the super-stream
        protected override void Dispose(bool disposing)
        {
            if (disposing && !_isDisposed)
            {
                _canRead = false;
                _isDisposed = true;
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class CheckSumAndSizeWriteStream : Stream
    {
        private readonly Stream _baseStream;
        private readonly Stream _baseBaseStream;
        private long _position;
        private uint _checksum;

        private readonly bool _leaveOpenOnClose;
        private readonly bool _canWrite;
        private bool _isDisposed;

        private bool _everWritten;

        // this is the position in BaseBaseStream
        private long _initialPosition;
        private readonly ZipArchiveEntry _zipArchiveEntry;
        private readonly EventHandler? _onClose;
        // Called when the stream is closed.
        // parameters are initialPosition, currentPosition, checkSum, baseBaseStream, zipArchiveEntry and onClose handler
        private readonly Action<long, long, uint, Stream, ZipArchiveEntry, EventHandler?> _saveCrcAndSizes;

        // parameters to saveCrcAndSizes are
        // initialPosition (initialPosition in baseBaseStream),
        // currentPosition (in this CheckSumAndSizeWriteStream),
        // checkSum (of data passed into this CheckSumAndSizeWriteStream),
        // baseBaseStream it's a backingStream, passed here so as to avoid closure allocation,
        // zipArchiveEntry passed here so as to avoid closure allocation,
        // onClose handler passed here so as to avoid closure allocation
        public CheckSumAndSizeWriteStream(Stream baseStream, Stream baseBaseStream, bool leaveOpenOnClose,
            ZipArchiveEntry entry, EventHandler? onClose,
            Action<long, long, uint, Stream, ZipArchiveEntry, EventHandler?> saveCrcAndSizes)
        {
            _baseStream = baseStream;
            _baseBaseStream = baseBaseStream;
            _position = 0;
            _checksum = 0;
            _leaveOpenOnClose = leaveOpenOnClose;
            _canWrite = true;
            _isDisposed = false;
            _initialPosition = 0;
            _zipArchiveEntry = entry;
            _onClose = onClose;
            _saveCrcAndSizes = saveCrcAndSizes;
        }

        public override long Length
        {
            get
            {
                ThrowIfDisposed();
                throw new NotSupportedException(SR.SeekingNotSupported);
            }
        }

        public override long Position
        {
            get
            {
                ThrowIfDisposed();
                return _position;
            }
            set
            {
                ThrowIfDisposed();
                throw new NotSupportedException(SR.SeekingNotSupported);
            }
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => _canWrite;

        private void ThrowIfDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().ToString(), SR.HiddenStreamName);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.ReadingNotSupported);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.ReadingNotSupported);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.ReadingNotSupported);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.SeekingNotSupported);
        }

        public override void SetLength(long value)
        {
            ThrowIfDisposed();
            throw new NotSupportedException(SR.SetLengthRequiresSeekingAndWriting);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            // we can't pass the argument checking down a level
            ValidateBufferArguments(buffer, offset, count);

            // if we're not actually writing anything, we don't want to trigger as if we did write something
            ThrowIfDisposed();
            Debug.Assert(CanWrite);

            if (count == 0)
                return;

            if (!_everWritten)
            {
                _initialPosition = _baseBaseStream.Position;
                _everWritten = true;
            }

            _checksum = Crc32Helper.UpdateCrc32(_checksum, buffer, offset, count);
            _baseStream.Write(buffer, offset, count);
            _position += count;
        }

        public override void Write(ReadOnlySpan<byte> source)
        {
            // if we're not actually writing anything, we don't want to trigger as if we did write something
            ThrowIfDisposed();
            Debug.Assert(CanWrite);

            if (source.Length == 0)
                return;

            if (!_everWritten)
            {
                _initialPosition = _baseBaseStream.Position;
                _everWritten = true;
            }

            _checksum = Crc32Helper.UpdateCrc32(_checksum, source);
            _baseStream.Write(source);
            _position += source.Length;
        }

        public override void WriteByte(byte value) =>
            Write(new ReadOnlySpan<byte>(in value));

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBufferArguments(buffer, offset, count);
            return WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken).AsTask();
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            Debug.Assert(CanWrite);

            return !buffer.IsEmpty ?
                Core(buffer, cancellationToken) :
                default;

            async ValueTask Core(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (!_everWritten)
                {
                    _initialPosition = _baseBaseStream.Position;
                    _everWritten = true;
                }

                _checksum = Crc32Helper.UpdateCrc32(_checksum, buffer.Span);

                await _baseStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                _position += buffer.Length;
            }
        }

        public override void Flush()
        {
            ThrowIfDisposed();

            // assume writable if not disposed
            Debug.Assert(CanWrite);

            _baseStream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            return _baseStream.FlushAsync(cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_isDisposed)
            {
                // if we never wrote through here, save the position
                if (!_everWritten)
                    _initialPosition = _baseBaseStream.Position;
                if (!_leaveOpenOnClose)
                    _baseStream.Dispose(); // Close my super-stream (flushes the last data)
                _saveCrcAndSizes?.Invoke(_initialPosition, Position, _checksum, _baseBaseStream, _zipArchiveEntry, _onClose);
                _isDisposed = true;
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (!_isDisposed)
            {
                // if we never wrote through here, save the position
                if (!_everWritten)
                    _initialPosition = _baseBaseStream.Position;
                if (!_leaveOpenOnClose)
                    await _baseStream.DisposeAsync().ConfigureAwait(false); // Close my super-stream (flushes the last data)
                _saveCrcAndSizes?.Invoke(_initialPosition, Position, _checksum, _baseBaseStream, _zipArchiveEntry, _onClose);
                _isDisposed = true;
            }
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }
}
