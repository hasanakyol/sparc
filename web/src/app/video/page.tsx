'use client';

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Play, Pause, Square, RotateCcw, Download, Settings, Grid3X3, Maximize2, Minimize2, Eye, EyeOff, Calendar, Clock, Search, Filter, AlertTriangle, Camera, Building, MapPin, Volume2, VolumeX, SkipBack, SkipForward, Rewind, FastForward, Loader2, RefreshCw, Plus, Edit, Trash2 } from 'lucide-react';
import { toast } from 'react-hot-toast';
import apiClient from '@/lib/api';
import { useRealtime } from '@/hooks/useRealtime';
import { useAuth } from '@/hooks/useAuth';
import {
  Camera as CameraType,
  Building as BuildingType,
  Floor as FloorType,
  AccessEvent as AccessEventType,
  VideoRecording,
  VideoStream,
  VideoPlaybackRequest,
  PrivacyMask as PrivacyMaskType,
  VideoExportLog,
  CreatePrivacyMaskDTO,
  UpdatePrivacyMaskDTO,
  CreateVideoExportLogDTO,
} from '@sparc/shared';

// Extended types for UI
interface ExtendedCamera extends CameraType {
  streamUrl?: string;
  recordingUrl?: string;
  privacyMasks: PrivacyMaskType[];
}

interface VideoExport {
  id: string;
  cameraId: string;
  startTime: Date;
  endTime: Date;
  format: 'mp4' | 'avi';
  quality: 'high' | 'medium' | 'low';
  includeAudio: boolean;
  watermark: boolean;
  chainOfCustody: boolean;
}

interface CameraGroup {
  id: string;
  name: string;
  cameraIds: string[];
  description?: string;
}

interface VideoMetadata {
  duration: number;
  startTime: Date;
  endTime: Date;
  events: AccessEventType[];
}

// Grid layout options
const GRID_LAYOUTS = [
  { name: '1x1', cols: 1, rows: 1, max: 1 },
  { name: '2x2', cols: 2, rows: 2, max: 4 },
  { name: '3x3', cols: 3, rows: 3, max: 9 },
  { name: '4x4', cols: 4, rows: 4, max: 16 },
  { name: '5x5', cols: 5, rows: 5, max: 25 },
  { name: '6x6', cols: 6, rows: 6, max: 36 },
  { name: '8x8', cols: 8, rows: 8, max: 64 },
];

// Loading states
interface LoadingStates {
  buildings: boolean;
  floors: boolean;
  cameras: boolean;
  accessEvents: boolean;
  videoStream: { [cameraId: string]: boolean };
  videoExport: boolean;
  privacyMasks: boolean;
}

// Error states
interface ErrorStates {
  buildings: string | null;
  floors: string | null;
  cameras: string | null;
  accessEvents: string | null;
  videoStream: { [cameraId: string]: string | null };
  videoExport: string | null;
  privacyMasks: string | null;
}

// Video Player Component
const VideoPlayer: React.FC<{
  camera: ExtendedCamera;
  isLive: boolean;
  onTimeUpdate?: (time: number) => void;
  currentTime?: number;
  isFullscreen?: boolean;
  onToggleFullscreen?: () => void;
  showControls?: boolean;
  onPrivacyMaskUpdate?: () => void;
}> = ({ camera, isLive, onTimeUpdate, currentTime, isFullscreen, onToggleFullscreen, showControls = true, onPrivacyMaskUpdate }) => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(1);
  const [isMuted, setIsMuted] = useState(false);
  const [showPrivacyMasks, setShowPrivacyMasks] = useState(true);
  const [streamUrl, setStreamUrl] = useState<string | null>(null);
  const [isLoadingStream, setIsLoadingStream] = useState(false);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [isCreatingMask, setIsCreatingMask] = useState(false);
  const [newMaskCoords, setNewMaskCoords] = useState<{ x: number; y: number; width: number; height: number } | null>(null);

  // Load camera stream
  useEffect(() => {
    const loadStream = async () => {
      if (!camera.id) return;

      setIsLoadingStream(true);
      setStreamError(null);

      try {
        if (isLive) {
          // Get live stream
          const stream = await apiClient.getCameraStream(camera.id, 'high');
          setStreamUrl(stream.streamUrl);
        } else if (camera.recordingUrl) {
          // Use recording URL for playback
          setStreamUrl(camera.recordingUrl);
        }
      } catch (error) {
        console.error('Failed to load camera stream:', error);
        setStreamError(error instanceof Error ? error.message : 'Failed to load stream');
        toast.error(`Failed to load stream for ${camera.name}`);
      } finally {
        setIsLoadingStream(false);
      }
    };

    loadStream();
  }, [camera.id, isLive, camera.recordingUrl]);

  // Handle privacy mask creation
  const handleVideoClick = useCallback((e: React.MouseEvent<HTMLVideoElement>) => {
    if (!isCreatingMask || !videoRef.current) return;

    const rect = videoRef.current.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;

    if (!newMaskCoords) {
      // Start creating mask
      setNewMaskCoords({ x, y, width: 0, height: 0 });
    } else {
      // Finish creating mask
      const width = Math.abs(x - newMaskCoords.x);
      const height = Math.abs(y - newMaskCoords.y);
      const finalX = Math.min(x, newMaskCoords.x);
      const finalY = Math.min(y, newMaskCoords.y);

      createPrivacyMask({
        x: finalX,
        y: finalY,
        width,
        height,
      });

      setNewMaskCoords(null);
      setIsCreatingMask(false);
    }
  }, [isCreatingMask, newMaskCoords]);

  const createPrivacyMask = async (coordinates: { x: number; y: number; width: number; height: number }) => {
    try {
      const maskData: CreatePrivacyMaskDTO = {
        cameraId: camera.id,
        name: `Privacy Mask ${camera.privacyMasks.length + 1}`,
        coordinates,
        enabled: true,
      };

      await apiClient.post('/api/v1/privacy-masks', maskData);
      toast.success('Privacy mask created successfully');
      onPrivacyMaskUpdate?.();
    } catch (error) {
      console.error('Failed to create privacy mask:', error);
      toast.error('Failed to create privacy mask');
    }
  };

  const togglePrivacyMask = async (maskId: string, enabled: boolean) => {
    try {
      await apiClient.patch(`/api/v1/privacy-masks/${maskId}`, { enabled });
      toast.success(`Privacy mask ${enabled ? 'enabled' : 'disabled'}`);
      onPrivacyMaskUpdate?.();
    } catch (error) {
      console.error('Failed to toggle privacy mask:', error);
      toast.error('Failed to update privacy mask');
    }
  };

  const deletePrivacyMask = async (maskId: string) => {
    try {
      await apiClient.delete(`/api/v1/privacy-masks/${maskId}`);
      toast.success('Privacy mask deleted');
      onPrivacyMaskUpdate?.();
    } catch (error) {
      console.error('Failed to delete privacy mask:', error);
      toast.error('Failed to delete privacy mask');
    }
  };

  useEffect(() => {
    if (videoRef.current && currentTime !== undefined) {
      videoRef.current.currentTime = currentTime;
    }
  }, [currentTime]);

  const handlePlayPause = () => {
    if (videoRef.current) {
      if (isPlaying) {
        videoRef.current.pause();
      } else {
        videoRef.current.play().catch(error => {
          console.error('Failed to play video:', error);
          toast.error('Failed to play video');
        });
      }
      setIsPlaying(!isPlaying);
    }
  };

  const handleTimeUpdate = () => {
    if (videoRef.current && onTimeUpdate) {
      onTimeUpdate(videoRef.current.currentTime);
    }
  };

  const handleLoadedMetadata = () => {
    if (videoRef.current) {
      setDuration(videoRef.current.duration);
    }
  };

  const handleVolumeChange = (newVolume: number) => {
    setVolume(newVolume);
    if (videoRef.current) {
      videoRef.current.volume = newVolume;
    }
  };

  const toggleMute = () => {
    setIsMuted(!isMuted);
    if (videoRef.current) {
      videoRef.current.muted = !isMuted;
    }
  };

  const handleVideoError = (e: React.SyntheticEvent<HTMLVideoElement, Event>) => {
    const error = (e.target as HTMLVideoElement).error;
    const errorMessage = error ? `Video error: ${error.message}` : 'Unknown video error';
    console.error('Video playback error:', error);
    setStreamError(errorMessage);
    toast.error(`Playback error for ${camera.name}`);
  };

  return (
    <div className={`relative bg-black rounded-lg overflow-hidden ${isFullscreen ? 'fixed inset-0 z-50' : 'aspect-video'}`}>
      {/* Camera Status Indicator */}
      <div className="absolute top-2 left-2 z-10">
        <div className={`flex items-center gap-2 px-2 py-1 rounded text-xs font-medium ${
          camera.status === 'online' ? 'bg-green-500/80 text-white' :
          camera.status === 'offline' ? 'bg-red-500/80 text-white' :
          'bg-yellow-500/80 text-black'
        }`}>
          <div className={`w-2 h-2 rounded-full ${
            camera.status === 'online' ? 'bg-white' :
            camera.status === 'offline' ? 'bg-white' :
            'bg-black'
          }`} />
          {camera.status.toUpperCase()}
        </div>
      </div>

      {/* Camera Info */}
      <div className="absolute top-2 right-2 z-10">
        <div className="bg-black/60 text-white px-2 py-1 rounded text-xs">
          {camera.name}
        </div>
      </div>

      {/* Live Indicator */}
      {isLive && (
        <div className="absolute top-10 left-2 z-10">
          <div className="bg-red-500 text-white px-2 py-1 rounded text-xs font-bold flex items-center gap-1">
            <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
            LIVE
          </div>
        </div>
      )}

      {/* Loading Overlay */}
      {isLoadingStream && (
        <div className="absolute inset-0 bg-black/60 flex items-center justify-center">
          <div className="text-white text-center">
            <Loader2 size={48} className="mx-auto mb-2 animate-spin text-blue-400" />
            <div className="font-medium">Loading Stream...</div>
          </div>
        </div>
      )}

      {/* Video Element */}
      {streamUrl && !streamError && (
        <video
          ref={videoRef}
          className={`w-full h-full object-cover ${isCreatingMask ? 'cursor-crosshair' : ''}`}
          onTimeUpdate={handleTimeUpdate}
          onLoadedMetadata={handleLoadedMetadata}
          onPlay={() => setIsPlaying(true)}
          onPause={() => setIsPlaying(false)}
          onError={handleVideoError}
          onClick={handleVideoClick}
          muted={isMuted}
          playsInline
          autoPlay={isLive}
        >
          <source src={streamUrl} type="application/x-mpegURL" />
          <source src={streamUrl} type="video/mp4" />
          Your browser does not support the video tag.
        </video>
      )}

      {/* Stream Error Overlay */}
      {streamError && (
        <div className="absolute inset-0 bg-black/60 flex items-center justify-center">
          <div className="text-white text-center">
            <AlertTriangle size={48} className="mx-auto mb-2 text-red-400" />
            <div className="font-medium">Stream Error</div>
            <div className="text-sm text-gray-300 mt-1">{streamError}</div>
            <button
              onClick={() => {
                setStreamError(null);
                // Trigger stream reload
                const loadStream = async () => {
                  setIsLoadingStream(true);
                  try {
                    const stream = await apiClient.getCameraStream(camera.id, 'high');
                    setStreamUrl(stream.streamUrl);
                  } catch (error) {
                    setStreamError(error instanceof Error ? error.message : 'Failed to reload stream');
                  } finally {
                    setIsLoadingStream(false);
                  }
                };
                loadStream();
              }}
              className="mt-2 px-3 py-1 bg-blue-500 hover:bg-blue-600 rounded text-sm transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      )}

      {/* Privacy Masks */}
      {showPrivacyMasks && camera.privacyMasks.map(mask => (
        mask.enabled && (
          <div
            key={mask.id}
            className="absolute bg-black/80 border border-yellow-400 group"
            style={{
              left: `${mask.coordinates.x}%`,
              top: `${mask.coordinates.y}%`,
              width: `${mask.coordinates.width}%`,
              height: `${mask.coordinates.height}%`,
            }}
          >
            <div className="text-yellow-400 text-xs p-1">PRIVACY</div>
            <div className="absolute top-0 right-0 opacity-0 group-hover:opacity-100 transition-opacity">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  togglePrivacyMask(mask.id, false);
                }}
                className="bg-yellow-500 text-black p-1 rounded-bl text-xs hover:bg-yellow-400"
                title="Disable mask"
              >
                <EyeOff size={10} />
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  deletePrivacyMask(mask.id);
                }}
                className="bg-red-500 text-white p-1 rounded-bl text-xs hover:bg-red-400"
                title="Delete mask"
              >
                <Trash2 size={10} />
              </button>
            </div>
          </div>
        )
      ))}

      {/* New Privacy Mask Preview */}
      {isCreatingMask && newMaskCoords && (
        <div
          className="absolute bg-yellow-400/30 border-2 border-yellow-400 border-dashed"
          style={{
            left: `${newMaskCoords.x}%`,
            top: `${newMaskCoords.y}%`,
            width: `${newMaskCoords.width}%`,
            height: `${newMaskCoords.height}%`,
          }}
        >
          <div className="text-yellow-400 text-xs p-1">NEW MASK</div>
        </div>
      )}

      {/* Video Controls */}
      {showControls && (
        <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-4">
          <div className="flex items-center gap-2">
            <button
              onClick={handlePlayPause}
              className="text-white hover:text-blue-400 transition-colors"
            >
              {isPlaying ? <Pause size={20} /> : <Play size={20} />}
            </button>

            {!isLive && (
              <>
                <button className="text-white hover:text-blue-400 transition-colors">
                  <SkipBack size={16} />
                </button>
                <button className="text-white hover:text-blue-400 transition-colors">
                  <Rewind size={16} />
                </button>
                <button className="text-white hover:text-blue-400 transition-colors">
                  <FastForward size={16} />
                </button>
                <button className="text-white hover:text-blue-400 transition-colors">
                  <SkipForward size={16} />
                </button>
              </>
            )}

            {camera.hasAudio && (
              <>
                <button
                  onClick={toggleMute}
                  className="text-white hover:text-blue-400 transition-colors"
                >
                  {isMuted ? <VolumeX size={16} /> : <Volume2 size={16} />}
                </button>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={volume}
                  onChange={(e) => handleVolumeChange(Number(e.target.value))}
                  className="w-16"
                />
              </>
            )}

            <div className="flex-1" />

            <button
              onClick={() => setShowPrivacyMasks(!showPrivacyMasks)}
              className={`transition-colors ${showPrivacyMasks ? 'text-yellow-400' : 'text-white hover:text-blue-400'}`}
              title="Toggle privacy masks"
            >
              {showPrivacyMasks ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>

            <button
              onClick={() => setIsCreatingMask(!isCreatingMask)}
              className={`transition-colors ${isCreatingMask ? 'text-yellow-400' : 'text-white hover:text-blue-400'}`}
              title="Create privacy mask"
            >
              <Plus size={16} />
            </button>

            {onToggleFullscreen && (
              <button
                onClick={onToggleFullscreen}
                className="text-white hover:text-blue-400 transition-colors"
                title="Toggle fullscreen"
              >
                {isFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
              </button>
            )}
          </div>
        </div>
      )}

      {/* Offline Overlay */}
      {camera.status === 'offline' && (
        <div className="absolute inset-0 bg-black/60 flex items-center justify-center">
          <div className="text-white text-center">
            <AlertTriangle size={48} className="mx-auto mb-2 text-red-400" />
            <div className="font-medium">Camera Offline</div>
            <div className="text-sm text-gray-300">Attempting to reconnect...</div>
          </div>
        </div>
      )}
    </div>
  );
};

// Timeline Scrubber Component
const TimelineScrubber: React.FC<{
  duration: number;
  currentTime: number;
  onTimeChange: (time: number) => void;
  events?: AccessEventType[];
  metadata?: VideoMetadata;
}> = ({ duration, currentTime, onTimeChange, events = [], metadata }) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleMouseDown = () => setIsDragging(true);
  const handleMouseUp = () => setIsDragging(false);

  const handleTimelineClick = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const percentage = clickX / rect.width;
    const newTime = percentage * duration;
    onTimeChange(newTime);
  };

  const formatTime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="bg-gray-800 p-4 rounded-lg">
      <div className="flex items-center gap-4 mb-2">
        <span className="text-white text-sm">{formatTime(currentTime)}</span>
        <div className="flex-1 relative">
          <div
            className="h-2 bg-gray-600 rounded-full cursor-pointer relative"
            onClick={handleTimelineClick}
          >
            {/* Progress bar */}
            <div
              className="h-full bg-blue-500 rounded-full"
              style={{ width: `${(currentTime / duration) * 100}%` }}
            />
            
            {/* Event markers */}
            {events.map(event => {
              // Calculate event position based on video metadata
              let position = 0;
              if (metadata) {
                const eventTime = new Date(event.timestamp).getTime();
                const startTime = metadata.startTime.getTime();
                const endTime = metadata.endTime.getTime();
                const totalDuration = endTime - startTime;
                const eventOffset = eventTime - startTime;
                position = (eventOffset / totalDuration) * 100;
              } else {
                // Fallback calculation
                const eventTime = (new Date(event.timestamp).getTime() - Date.now() + duration * 1000) / 1000;
                position = (eventTime / duration) * 100;
              }

              if (position >= 0 && position <= 100) {
                return (
                  <div
                    key={event.id}
                    className={`absolute top-0 w-1 h-full cursor-pointer ${
                      event.eventType === 'access_granted' ? 'bg-green-400' :
                      event.eventType === 'access_denied' ? 'bg-red-400' :
                      event.eventType === 'door_forced' ? 'bg-red-600' :
                      event.eventType === 'tailgating_detected' ? 'bg-orange-400' :
                      'bg-yellow-400'
                    }`}
                    style={{ left: `${position}%` }}
                    title={`${event.eventType.toUpperCase()}: ${event.userId || 'Unknown'} at ${new Date(event.timestamp).toLocaleTimeString()}`}
                    onClick={() => {
                      // Jump to event time
                      if (metadata) {
                        const eventTime = new Date(event.timestamp).getTime();
                        const startTime = metadata.startTime.getTime();
                        const eventOffset = (eventTime - startTime) / 1000;
                        onTimeChange(eventOffset);
                      }
                    }}
                  />
                );
              }
              return null;
            })}

            {/* Playhead */}
            <div
              className="absolute top-1/2 w-4 h-4 bg-white rounded-full border-2 border-blue-500 transform -translate-y-1/2 cursor-grab"
              style={{ left: `${(currentTime / duration) * 100}%` }}
              onMouseDown={handleMouseDown}
            />
          </div>
        </div>
        <span className="text-white text-sm">{formatTime(duration)}</span>
      </div>
      
      {/* Timeline controls */}
      <div className="flex items-center justify-between text-xs text-gray-400">
        <div className="flex items-center gap-2">
          <Calendar size={14} />
          <span>{metadata ? metadata.startTime.toLocaleDateString() : 'Today'}</span>
          <Clock size={14} />
          <span>
            {metadata 
              ? `${metadata.startTime.toLocaleTimeString()} - ${metadata.endTime.toLocaleTimeString()}`
              : '00:00 - 23:59'
            }
          </span>
        </div>
        <div className="flex items-center gap-4">
          <span>{events.length} events</span>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span>Access Granted</span>
            <div className="w-2 h-2 bg-red-400 rounded-full"></div>
            <span>Access Denied</span>
            <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
            <span>Security Alert</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Main Video Management Page
export default function VideoPage() {
  const { user, tenant } = useAuth();
  
  // State management
  const [buildings, setBuildings] = useState<BuildingType[]>([]);
  const [floors, setFloors] = useState<FloorType[]>([]);
  const [cameras, setCameras] = useState<ExtendedCamera[]>([]);
  const [accessEvents, setAccessEvents] = useState<AccessEventType[]>([]);
  const [cameraGroups, setCameraGroups] = useState<CameraGroup[]>([]);
  const [videoMetadata, setVideoMetadata] = useState<VideoMetadata | null>(null);
  
  const [selectedBuilding, setSelectedBuilding] = useState<string>('');
  const [selectedFloor, setSelectedFloor] = useState<string>('');
  const [selectedCameras, setSelectedCameras] = useState<ExtendedCamera[]>([]);
  const [gridLayout, setGridLayout] = useState(GRID_LAYOUTS[2]); // 3x3 default
  const [isLive, setIsLive] = useState(true);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(3600); // 1 hour default
  const [fullscreenCamera, setFullscreenCamera] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedCameraForExport, setSelectedCameraForExport] = useState<ExtendedCamera | null>(null);
  const [selectedDate, setSelectedDate] = useState<string>(new Date().toISOString().split('T')[0]);
  const [selectedTimeRange, setSelectedTimeRange] = useState({ start: '00:00', end: '23:59' });

  // Loading and error states
  const [loading, setLoading] = useState<LoadingStates>({
    buildings: false,
    floors: false,
    cameras: false,
    accessEvents: false,
    videoStream: {},
    videoExport: false,
    privacyMasks: false,
  });

  const [errors, setErrors] = useState<ErrorStates>({
    buildings: null,
    floors: null,
    cameras: null,
    accessEvents: null,
    videoStream: {},
    videoExport: null,
    privacyMasks: null,
  });

  // Real-time connection
  const realtimeConfig = {
    tenantId: tenant?.id || '',
    token: user ? 'token' : '', // This should come from auth context
    autoConnect: true,
    subscriptions: {
      buildings: selectedBuilding ? [selectedBuilding] : [],
      floors: selectedFloor ? [{ buildingId: selectedBuilding, floorId: selectedFloor }] : [],
      cameras: selectedCameras.map(c => c.id),
    },
    handlers: {
      onVideoEvent: (event: any) => {
        console.log('Video event received:', event);
        toast.info(`Camera ${event.cameraId}: ${event.eventType}`);
      },
      onDeviceStatus: (status: any) => {
        if (status.deviceType === 'camera') {
          // Update camera status
          setCameras(prev => prev.map(camera => 
            camera.id === status.deviceId 
              ? { ...camera, status: status.status }
              : camera
          ));
        }
      },
      onAlert: (alert: any) => {
        if (alert.type === 'security' || alert.type === 'system') {
          toast.error(`${alert.severity.toUpperCase()}: ${alert.title}`);
        }
      },
    },
  };

  const realtime = useRealtime(realtimeConfig);

  // Data loading functions
  const loadBuildings = useCallback(async () => {
    setLoading(prev => ({ ...prev, buildings: true }));
    setErrors(prev => ({ ...prev, buildings: null }));

    try {
      const response = await apiClient.getBuildings();
      setBuildings(response.data);
      
      // Auto-select first building if none selected
      if (!selectedBuilding && response.data.length > 0) {
        setSelectedBuilding(response.data[0].id);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load buildings';
      setErrors(prev => ({ ...prev, buildings: errorMessage }));
      toast.error('Failed to load buildings');
      console.error('Failed to load buildings:', error);
    } finally {
      setLoading(prev => ({ ...prev, buildings: false }));
    }
  }, [selectedBuilding]);

  const loadFloors = useCallback(async (buildingId: string) => {
    if (!buildingId) return;

    setLoading(prev => ({ ...prev, floors: true }));
    setErrors(prev => ({ ...prev, floors: null }));

    try {
      const response = await apiClient.getFloors({ buildingId });
      setFloors(response.data);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load floors';
      setErrors(prev => ({ ...prev, floors: errorMessage }));
      toast.error('Failed to load floors');
      console.error('Failed to load floors:', error);
    } finally {
      setLoading(prev => ({ ...prev, floors: false }));
    }
  }, []);

  const loadCameras = useCallback(async (buildingId?: string, floorId?: string) => {
    setLoading(prev => ({ ...prev, cameras: true }));
    setErrors(prev => ({ ...prev, cameras: null }));

    try {
      const params: any = {};
      if (buildingId) params.buildingId = buildingId;
      if (floorId) params.floorId = floorId;

      const response = await apiClient.getCameras(params);
      
      // Load privacy masks for each camera
      const camerasWithMasks = await Promise.all(
        response.data.map(async (camera) => {
          try {
            const masksResponse = await apiClient.get(`/api/v1/privacy-masks?cameraId=${camera.id}`);
            return {
              ...camera,
              privacyMasks: masksResponse.data || [],
            };
          } catch (error) {
            console.error(`Failed to load privacy masks for camera ${camera.id}:`, error);
            return {
              ...camera,
              privacyMasks: [],
            };
          }
        })
      );

      setCameras(camerasWithMasks);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load cameras';
      setErrors(prev => ({ ...prev, cameras: errorMessage }));
      toast.error('Failed to load cameras');
      console.error('Failed to load cameras:', error);
    } finally {
      setLoading(prev => ({ ...prev, cameras: false }));
    }
  }, []);

  const loadAccessEvents = useCallback(async (cameraIds?: string[]) => {
    setLoading(prev => ({ ...prev, accessEvents: true }));
    setErrors(prev => ({ ...prev, accessEvents: null }));

    try {
      const params: any = {
        limit: 100,
        sortBy: 'timestamp',
        sortOrder: 'desc',
      };

      if (cameraIds && cameraIds.length > 0) {
        params.cameraIds = cameraIds;
      }

      if (selectedBuilding) {
        params.buildingId = selectedBuilding;
      }

      if (selectedFloor) {
        params.floorId = selectedFloor;
      }

      // Add date range filter for recorded video
      if (!isLive) {
        const startDate = new Date(`${selectedDate}T${selectedTimeRange.start}:00`);
        const endDate = new Date(`${selectedDate}T${selectedTimeRange.end}:59`);
        params.startTime = startDate.toISOString();
        params.endTime = endDate.toISOString();
      }

      const response = await apiClient.getAccessEvents(params);
      setAccessEvents(response.data);

      // Update video metadata for timeline
      if (!isLive && response.data.length > 0) {
        const startDate = new Date(`${selectedDate}T${selectedTimeRange.start}:00`);
        const endDate = new Date(`${selectedDate}T${selectedTimeRange.end}:59`);
        const duration = (endDate.getTime() - startDate.getTime()) / 1000;
        
        setVideoMetadata({
          duration,
          startTime: startDate,
          endTime: endDate,
          events: response.data,
        });
        setDuration(duration);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load access events';
      setErrors(prev => ({ ...prev, accessEvents: errorMessage }));
      toast.error('Failed to load access events');
      console.error('Failed to load access events:', error);
    } finally {
      setLoading(prev => ({ ...prev, accessEvents: false }));
    }
  }, [selectedBuilding, selectedFloor, isLive, selectedDate, selectedTimeRange]);

  // Load initial data
  useEffect(() => {
    if (tenant?.id) {
      loadBuildings();
    }
  }, [tenant?.id, loadBuildings]);

  useEffect(() => {
    if (selectedBuilding) {
      loadFloors(selectedBuilding);
      loadCameras(selectedBuilding, selectedFloor);
    }
  }, [selectedBuilding, selectedFloor, loadFloors, loadCameras]);

  useEffect(() => {
    const cameraIds = selectedCameras.map(c => c.id);
    if (cameraIds.length > 0) {
      loadAccessEvents(cameraIds);
    }
  }, [selectedCameras, loadAccessEvents]);

  // Filter cameras based on search
  const filteredCameras = cameras.filter(camera =>
    camera.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (camera.location && camera.location.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  // Initialize selected cameras
  useEffect(() => {
    if (filteredCameras.length > 0 && selectedCameras.length === 0) {
      setSelectedCameras(filteredCameras.slice(0, gridLayout.max));
    }
  }, [filteredCameras, selectedCameras.length, gridLayout.max]);

  // Update selected cameras when grid layout changes
  useEffect(() => {
    if (selectedCameras.length > gridLayout.max) {
      setSelectedCameras(selectedCameras.slice(0, gridLayout.max));
    }
  }, [gridLayout.max, selectedCameras]);

  const handleCameraSelect = (camera: ExtendedCamera) => {
    if (selectedCameras.find(c => c.id === camera.id)) {
      setSelectedCameras(selectedCameras.filter(c => c.id !== camera.id));
    } else if (selectedCameras.length < gridLayout.max) {
      setSelectedCameras([...selectedCameras, camera]);
    }
  };

  const handleExportVideo = (camera: ExtendedCamera) => {
    setSelectedCameraForExport(camera);
    setShowExportModal(true);
  };

  const toggleFullscreen = (cameraId: string) => {
    setFullscreenCamera(fullscreenCamera === cameraId ? null : cameraId);
  };

  const handlePrivacyMaskUpdate = () => {
    // Reload cameras to get updated privacy masks
    loadCameras(selectedBuilding, selectedFloor);
  };

  const handleVideoExport = async (exportData: VideoExport) => {
    setLoading(prev => ({ ...prev, videoExport: true }));
    setErrors(prev => ({ ...prev, videoExport: null }));

    try {
      const exportRequest: CreateVideoExportLogDTO = {
        cameraId: exportData.cameraId,
        startTime: exportData.startTime.toISOString(),
        endTime: exportData.endTime.toISOString(),
        format: exportData.format,
        quality: exportData.quality,
        includeAudio: exportData.includeAudio,
        watermark: exportData.watermark,
        chainOfCustody: exportData.chainOfCustody,
        requestedBy: user?.id || '',
        reason: 'Manual export from video management interface',
      };

      const result = await apiClient.exportVideo(exportRequest);
      toast.success('Video export started successfully');
      console.log('Export started:', result);
      
      // You could add a notification system to track export progress
      // or redirect to a downloads/exports page
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to start video export';
      setErrors(prev => ({ ...prev, videoExport: errorMessage }));
      toast.error('Failed to start video export');
      console.error('Failed to export video:', error);
    } finally {
      setLoading(prev => ({ ...prev, videoExport: false }));
    }
  };

  const requestVideoPlayback = async (cameraId: string, startTime: Date, endTime: Date) => {
    try {
      const playbackRequest: VideoPlaybackRequest = {
        cameraId,
        startTime: startTime.toISOString(),
        endTime: endTime.toISOString(),
        quality: 'high',
      };

      const response = await apiClient.requestVideoPlayback(playbackRequest);
      return response.playback_url;
    } catch (error) {
      console.error('Failed to request video playback:', error);
      toast.error('Failed to load recorded video');
      return null;
    }
  };

  // Handle live/recorded toggle
  const handleLiveToggle = async (live: boolean) => {
    setIsLive(live);
    
    if (!live) {
      // Load recorded video for selected cameras
      for (const camera of selectedCameras) {
        const startTime = new Date(`${selectedDate}T${selectedTimeRange.start}:00`);
        const endTime = new Date(`${selectedDate}T${selectedTimeRange.end}:59`);
        
        const playbackUrl = await requestVideoPlayback(camera.id, startTime, endTime);
        if (playbackUrl) {
          // Update camera with recording URL
          setCameras(prev => prev.map(c => 
            c.id === camera.id 
              ? { ...c, recordingUrl: playbackUrl }
              : c
          ));
        }
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Camera className="text-blue-400" />
              Video Management
            </h1>
            
            {/* Live/Recorded Toggle */}
            <div className="flex bg-gray-700 rounded-lg p-1">
              <button
                onClick={() => handleLiveToggle(true)}
                disabled={loading.cameras}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  isLive ? 'bg-red-500 text-white' : 'text-gray-300 hover:text-white'
                } ${loading.cameras ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
                  Live
                </div>
              </button>
              <button
                onClick={() => handleLiveToggle(false)}
                disabled={loading.cameras}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  !isLive ? 'bg-blue-500 text-white' : 'text-gray-300 hover:text-white'
                } ${loading.cameras ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                Recorded
              </button>
            </div>

            {/* Date/Time Range for Recorded Video */}
            {!isLive && (
              <div className="flex items-center gap-2">
                <input
                  type="date"
                  value={selectedDate}
                  onChange={(e) => setSelectedDate(e.target.value)}
                  className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm"
                />
                <input
                  type="time"
                  value={selectedTimeRange.start}
                  onChange={(e) => setSelectedTimeRange(prev => ({ ...prev, start: e.target.value }))}
                  className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm"
                />
                <span className="text-gray-400">to</span>
                <input
                  type="time"
                  value={selectedTimeRange.end}
                  onChange={(e) => setSelectedTimeRange(prev => ({ ...prev, end: e.target.value }))}
                  className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm"
                />
                <button
                  onClick={() => loadAccessEvents(selectedCameras.map(c => c.id))}
                  disabled={loading.accessEvents}
                  className="bg-blue-500 hover:bg-blue-600 disabled:opacity-50 px-3 py-1 rounded text-sm transition-colors"
                >
                  {loading.accessEvents ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                </button>
              </div>
            )}
          </div>

          {/* Grid Layout Selector */}
          <div className="flex items-center gap-4">
            <select
              value={gridLayout.name}
              onChange={(e) => {
                const layout = GRID_LAYOUTS.find(l => l.name === e.target.value);
                if (layout) setGridLayout(layout);
              }}
              className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm"
            >
              {GRID_LAYOUTS.map(layout => (
                <option key={layout.name} value={layout.name}>
                  {layout.name} Grid ({layout.max} cameras)
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="flex h-[calc(100vh-80px)]">
        {/* Sidebar */}
        <div className="w-80 bg-gray-800 border-r border-gray-700 flex flex-col">
          {/* Building/Floor Selector */}
          <div className="p-4 border-b border-gray-700">
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium mb-1">Building</label>
                <select
                  value={selectedBuilding}
                  onChange={(e) => {
                    setSelectedBuilding(e.target.value);
                    setSelectedFloor('');
                    setSelectedCameras([]);
                  }}
                  disabled={loading.buildings}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm disabled:opacity-50"
                >
                  <option value="">Select Building</option>
                  {buildings.map(building => (
                    <option key={building.id} value={building.id}>
                      {building.name}
                    </option>
                  ))}
                </select>
                {loading.buildings && (
                  <div className="flex items-center gap-2 mt-1 text-xs text-gray-400">
                    <Loader2 size={12} className="animate-spin" />
                    Loading buildings...
                  </div>
                )}
                {errors.buildings && (
                  <div className="text-red-400 text-xs mt-1">{errors.buildings}</div>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1">Floor</label>
                <select
                  value={selectedFloor}
                  onChange={(e) => {
                    setSelectedFloor(e.target.value);
                    setSelectedCameras([]);
                  }}
                  disabled={loading.floors || !selectedBuilding}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm disabled:opacity-50"
                >
                  <option value="">All Floors</option>
                  {floors.map(floor => (
                    <option key={floor.id} value={floor.id}>
                      {floor.name}
                    </option>
                  ))}
                </select>
                {loading.floors && (
                  <div className="flex items-center gap-2 mt-1 text-xs text-gray-400">
                    <Loader2 size={12} className="animate-spin" />
                    Loading floors...
                  </div>
                )}
                {errors.floors && (
                  <div className="text-red-400 text-xs mt-1">{errors.floors}</div>
                )}
              </div>
            </div>
          </div>

          {/* Search */}
          <div className="p-4 border-b border-gray-700">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={16} />
              <input
                type="text"
                placeholder="Search cameras..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg pl-10 pr-3 py-2 text-sm"
              />
            </div>
          </div>

          {/* Camera List */}
          <div className="flex-1 overflow-y-auto p-4">
            {loading.cameras ? (
              <div className="flex items-center justify-center h-32">
                <div className="text-center">
                  <Loader2 size={32} className="mx-auto mb-2 animate-spin text-blue-400" />
                  <div className="text-sm text-gray-400">Loading cameras...</div>
                </div>
              </div>
            ) : errors.cameras ? (
              <div className="flex items-center justify-center h-32">
                <div className="text-center">
                  <AlertTriangle size={32} className="mx-auto mb-2 text-red-400" />
                  <div className="text-sm text-red-400">{errors.cameras}</div>
                  <button
                    onClick={() => loadCameras(selectedBuilding, selectedFloor)}
                    className="mt-2 px-3 py-1 bg-blue-500 hover:bg-blue-600 rounded text-sm transition-colors"
                  >
                    Retry
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                {filteredCameras.map(camera => (
                  <div
                    key={camera.id}
                    onClick={() => handleCameraSelect(camera)}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                      selectedCameras.find(c => c.id === camera.id)
                        ? 'bg-blue-500/20 border-blue-500'
                        : 'bg-gray-700 border-gray-600 hover:border-gray-500'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="font-medium text-sm">{camera.name}</div>
                        <div className="text-xs text-gray-400 flex items-center gap-1">
                          <Building size={12} />
                          {buildings.find(b => b.id === camera.buildingId)?.name || 'Unknown Building'}
                        </div>
                        <div className="text-xs text-gray-400 flex items-center gap-1">
                          <MapPin size={12} />
                          {floors.find(f => f.id === camera.floorId)?.name || 'Unknown Floor'} - {camera.location || 'Unknown Zone'}
                        </div>
                      </div>
                      <div className={`w-3 h-3 rounded-full ${
                        camera.status === 'online' ? 'bg-green-400' :
                        camera.status === 'offline' ? 'bg-red-400' :
                        'bg-yellow-400'
                      }`} />
                    </div>
                    
                    {/* Camera capabilities */}
                    <div className="flex gap-1 mt-2">
                      {camera.capabilities?.ptz && (
                        <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-1 rounded">PTZ</span>
                      )}
                      {camera.capabilities?.audio && (
                        <span className="text-xs bg-green-500/20 text-green-400 px-2 py-1 rounded">Audio</span>
                      )}
                      {camera.capabilities?.nightVision && (
                        <span className="text-xs bg-purple-500/20 text-purple-400 px-2 py-1 rounded">Night</span>
                      )}
                      {camera.capabilities?.motionDetection && (
                        <span className="text-xs bg-orange-500/20 text-orange-400 px-2 py-1 rounded">Motion</span>
                      )}
                      {camera.privacyMasks.length > 0 && (
                        <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-1 rounded">
                          {camera.privacyMasks.length} Mask{camera.privacyMasks.length > 1 ? 's' : ''}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                
                {filteredCameras.length === 0 && !loading.cameras && (
                  <div className="text-center py-8 text-gray-400">
                    <Camera size={48} className="mx-auto mb-2" />
                    <div className="text-sm">No cameras found</div>
                    {searchTerm && (
                      <div className="text-xs mt-1">Try adjusting your search terms</div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Selected Cameras Info */}
          <div className="p-4 border-t border-gray-700">
            <div className="text-sm text-gray-400">
              Selected: {selectedCameras.length} / {gridLayout.max}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Video Grid */}
          <div className="flex-1 p-4">
            <div
              className="grid gap-2 h-full"
              style={{
                gridTemplateColumns: `repeat(${gridLayout.cols}, 1fr)`,
                gridTemplateRows: `repeat(${gridLayout.rows}, 1fr)`,
              }}
            >
              {Array.from({ length: gridLayout.max }).map((_, index) => {
                const camera = selectedCameras[index];
                return (
                  <div key={index} className="relative">
                    {camera ? (
                      <VideoPlayer
                        camera={camera}
                        isLive={isLive}
                        onTimeUpdate={setCurrentTime}
                        currentTime={isLive ? undefined : currentTime}
                        isFullscreen={fullscreenCamera === camera.id}
                        onToggleFullscreen={() => toggleFullscreen(camera.id)}
                        showControls={!isLive || fullscreenCamera === camera.id}
                        onPrivacyMaskUpdate={handlePrivacyMaskUpdate}
                      />
                    ) : (
                      <div className="w-full h-full bg-gray-800 rounded-lg border-2 border-dashed border-gray-600 flex items-center justify-center">
                        <div className="text-center text-gray-400">
                          <Camera size={48} className="mx-auto mb-2" />
                          <div className="text-sm">Select a camera</div>
                        </div>
                      </div>
                    )}
                    
                    {/* Camera Actions */}
                    {camera && (
                      <div className="absolute top-2 right-2 flex gap-1">
                        <button
                          onClick={() => handleExportVideo(camera)}
                          className="bg-black/60 text-white p-1 rounded hover:bg-black/80 transition-colors"
                          title="Export Video"
                        >
                          <Download size={14} />
                        </button>
                        <button
                          className="bg-black/60 text-white p-1 rounded hover:bg-black/80 transition-colors"
                          title="Camera Settings"
                        >
                          <Settings size={14} />
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Timeline (for recorded video) */}
          {!isLive && (
            <div className="p-4 border-t border-gray-700">
              <TimelineScrubber
                duration={duration}
                currentTime={currentTime}
                onTimeChange={setCurrentTime}
                events={accessEvents}
                metadata={videoMetadata}
              />
            </div>
          )}

          {/* Access Events Panel */}
          <div className="h-48 border-t border-gray-700 bg-gray-800 p-4">
            <h3 className="font-medium mb-3 flex items-center gap-2">
              <AlertTriangle size={16} className="text-yellow-400" />
              Recent Access Events
              {loading.accessEvents && <Loader2 size={14} className="animate-spin" />}
            </h3>
            
            {loading.accessEvents ? (
              <div className="flex items-center justify-center h-24">
                <div className="text-center">
                  <Loader2 size={24} className="mx-auto mb-2 animate-spin text-blue-400" />
                  <div className="text-xs text-gray-400">Loading events...</div>
                </div>
              </div>
            ) : errors.accessEvents ? (
              <div className="flex items-center justify-center h-24">
                <div className="text-center">
                  <AlertTriangle size={24} className="mx-auto mb-2 text-red-400" />
                  <div className="text-xs text-red-400">{errors.accessEvents}</div>
                </div>
              </div>
            ) : (
              <div className="space-y-2 max-h-32 overflow-y-auto">
                {accessEvents.map(event => (
                  <div
                    key={event.id}
                    className="flex items-center justify-between p-2 bg-gray-700 rounded text-sm cursor-pointer hover:bg-gray-600 transition-colors"
                    onClick={() => {
                      // Jump to event time in timeline
                      if (!isLive && videoMetadata) {
                        const eventTime = new Date(event.timestamp).getTime();
                        const startTime = videoMetadata.startTime.getTime();
                        const eventOffset = (eventTime - startTime) / 1000;
                        setCurrentTime(eventOffset);
                      }
                    }}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        event.eventType === 'access_granted' ? 'bg-green-400' :
                        event.eventType === 'access_denied' ? 'bg-red-400' :
                        event.eventType === 'door_forced' ? 'bg-red-600' :
                        event.eventType === 'tailgating_detected' ? 'bg-orange-400' :
                        'bg-yellow-400'
                      }`} />
                      <div>
                        <div className="font-medium">{event.userId || 'Unknown User'}</div>
                        <div className="text-gray-400 text-xs">
                          {buildings.find(b => b.id === event.buildingId)?.name || 'Unknown Location'}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`font-medium text-xs ${
                        event.eventType === 'access_granted' ? 'text-green-400' :
                        event.eventType === 'access_denied' ? 'text-red-400' :
                        event.eventType === 'door_forced' ? 'text-red-600' :
                        event.eventType === 'tailgating_detected' ? 'text-orange-400' :
                        'text-yellow-400'
                      }`}>
                        {event.eventType.replace('_', ' ').toUpperCase()}
                      </div>
                      <div className="text-gray-400 text-xs">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                ))}
                
                {accessEvents.length === 0 && (
                  <div className="text-center py-4 text-gray-400">
                    <div className="text-sm">No access events found</div>
                    <div className="text-xs mt-1">
                      {isLive ? 'Events will appear here as they occur' : 'No events in selected time range'}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Export Modal */}
      {showExportModal && selectedCameraForExport && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-96">
            <h3 className="text-lg font-medium mb-4">Export Video</h3>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                
                const exportData: VideoExport = {
                  id: '',
                  cameraId: selectedCameraForExport.id,
                  startTime: new Date(formData.get('startTime') as string),
                  endTime: new Date(formData.get('endTime') as string),
                  format: formData.get('format') as 'mp4' | 'avi',
                  quality: formData.get('quality') as 'high' | 'medium' | 'low',
                  includeAudio: formData.has('includeAudio'),
                  watermark: formData.has('watermark'),
                  chainOfCustody: formData.has('chainOfCustody'),
                };

                handleVideoExport(exportData);
                setShowExportModal(false);
              }}
              className="space-y-4"
            >
              <div>
                <label className="block text-sm font-medium mb-1">Camera</label>
                <div className="text-sm text-gray-400">{selectedCameraForExport.name}</div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Start Time</label>
                  <input
                    name="startTime"
                    type="datetime-local"
                    required
                    defaultValue={new Date(Date.now() - 3600000).toISOString().slice(0, 16)}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">End Time</label>
                  <input
                    name="endTime"
                    type="datetime-local"
                    required
                    defaultValue={new Date().toISOString().slice(0, 16)}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Quality</label>
                <select name="quality" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm">
                  <option value="high">High (1080p)</option>
                  <option value="medium">Medium (720p)</option>
                  <option value="low">Low (480p)</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Format</label>
                <select name="format" className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm">
                  <option value="mp4">MP4</option>
                  <option value="avi">AVI</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="flex items-center gap-2">
                  <input name="includeAudio" type="checkbox" className="rounded" defaultChecked />
                  <span className="text-sm">Include audio</span>
                </label>
                <label className="flex items-center gap-2">
                  <input name="watermark" type="checkbox" className="rounded" defaultChecked />
                  <span className="text-sm">Add digital watermark</span>
                </label>
                <label className="flex items-center gap-2">
                  <input name="chainOfCustody" type="checkbox" className="rounded" defaultChecked />
                  <span className="text-sm">Include chain of custody</span>
                </label>
              </div>

              {errors.videoExport && (
                <div className="text-red-400 text-sm">{errors.videoExport}</div>
              )}

              <div className="flex gap-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowExportModal(false)}
                  disabled={loading.videoExport}
                  className="flex-1 px-4 py-2 bg-gray-600 hover:bg-gray-500 disabled:opacity-50 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading.videoExport}
                  className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {loading.videoExport ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      Exporting...
                    </>
                  ) : (
                    'Export'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Real-time Connection Status */}
      {!realtime.isConnected && (
        <div className="fixed bottom-4 right-4 bg-yellow-500 text-black px-4 py-2 rounded-lg shadow-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} />
            <span className="text-sm font-medium">Real-time connection lost</span>
          </div>
        </div>
      )}
    </div>
  );
}
