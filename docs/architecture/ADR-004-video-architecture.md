# ADR-004: Video Processing and Streaming Architecture

## Status
Accepted

## Context
SPARC must handle 100,000+ concurrent video streams with low latency (<500ms), support multiple video formats, enable real-time analytics, and provide reliable recording and playback capabilities.

## Decision
We will implement a distributed video architecture:

### Streaming Protocol
- **Primary**: WebRTC for ultra-low latency
- **Fallback**: HLS for compatibility
- **Recording**: Segmented MP4 with HLS

### Architecture Components
1. **Edge Servers**: WebRTC SFU (Selective Forwarding Unit)
2. **Transcoding**: FFmpeg with hardware acceleration
3. **Storage**: Object storage (S3) with CDN
4. **Analytics**: Real-time video analysis pipeline

### Processing Pipeline
```
Camera → Edge Server → Transcoding → Storage
                ↓           ↓          ↓
             WebRTC      Analytics    HLS/CDN
                ↓                       ↓
             Clients ← ← ← ← ← ← ← Clients
```

## Implementation

### Video Formats
```yaml
input_formats:
  - H.264/AVC
  - H.265/HEVC
  - VP8/VP9

output_profiles:
  - name: mobile
    resolution: 426x240
    bitrate: 400kbps
  - name: sd
    resolution: 640x360
    bitrate: 800kbps
  - name: hd
    resolution: 1280x720
    bitrate: 2500kbps
  - name: full_hd
    resolution: 1920x1080
    bitrate: 5000kbps
```

### Latency Optimizations
1. GeoDNS for edge server selection
2. UDP for WebRTC where possible
3. Adaptive bitrate based on network
4. Preemptive connection warming
5. Hardware acceleration for transcoding

## Consequences

### Positive
- Ultra-low latency with WebRTC
- Scalable with edge architecture
- Good compatibility with HLS fallback
- Efficient bandwidth usage

### Negative
- Complex WebRTC implementation
- Higher infrastructure costs
- Requires careful capacity planning
- WebRTC browser compatibility issues

## Alternatives Considered
1. **Pure HLS**: Simpler but 10-30s latency
2. **RTMP**: Good latency but dying protocol
3. **Custom Protocol**: Flexible but high maintenance
4. **SRT**: Good for contribution but not distribution