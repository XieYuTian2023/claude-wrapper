//! Count encrypted tunnel traffic for adaptive probing without decoding it.
use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) struct Activity {
    connections: AtomicU64,
    bytes: AtomicU64,
}

pub(super) struct Sample {
    pub connections: u64,
    pub bytes: u64,
}

impl Sample {
    pub fn busy(&self) -> bool {
        self.connections >= 3 || self.bytes >= 32 * 1024
    }
}

impl Activity {
    pub fn connected(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn take(&self) -> Sample {
        Sample {
            connections: self.connections.swap(0, Ordering::Relaxed),
            bytes: self.bytes.swap(0, Ordering::Relaxed),
        }
    }

    fn record_bytes(&self, count: usize) {
        if count != 0 {
            self.bytes.fetch_add(count as u64, Ordering::Relaxed);
        }
    }
}

pub(super) struct Observed<'a, T> {
    pub stream: T,
    pub activity: &'a Activity,
}

impl<T: AsyncRead + Unpin> AsyncRead for Observed<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = result {
            self.activity.record_bytes(buffer.filled().len() - before);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Observed<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = result {
            self.activity.record_bytes(count);
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write_vectored(cx, bytes);
        if let Poll::Ready(Ok(count)) = result {
            self.activity.record_bytes(count);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn reused_tunnel_counts_transferred_bytes_and_samples_reset() {
        let activity = Activity::default();
        let (stream, mut peer) = duplex(64 * 1024);
        let mut observed = Observed {
            stream,
            activity: &activity,
        };
        let mut bytes = vec![0u8; 32 * 1024];
        peer.write_all(&bytes).await.unwrap();
        observed.read_exact(&mut bytes).await.unwrap();
        observed.write_all(b"reply").await.unwrap();
        let sample = activity.take();
        assert_eq!(sample.connections, 0);
        assert_eq!(sample.bytes, (bytes.len() + 5) as u64);
        assert!(sample.busy());
        assert!(!activity.take().busy());
    }
}
