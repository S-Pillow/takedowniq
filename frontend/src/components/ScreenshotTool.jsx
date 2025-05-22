import { useState, useRef, useEffect } from 'react';
import { XMarkIcon, CameraIcon, ArrowUpOnSquareIcon, StopIcon } from '@heroicons/react/24/outline';

const ScreenshotTool = ({ onScreenshotCaptured, onCancel }) => {
  const [isSelecting, setIsSelecting] = useState(false); // True when selection mode is active (after stream starts)
  const [startPos, setStartPos] = useState({ x: 0, y: 0 });
  const [endPos, setEndPos] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false); // True when mouse is being dragged to select
  const [stream, setStream] = useState(null); // Holds the MediaStream object

  const canvasRef = useRef(null); // Main canvas for displaying video and drawing selection
  const videoRef = useRef(null); // Hidden video element, source for the canvas
  const selectionRef = useRef(null); // Div for visually showing the selection rectangle

  const animationFrameId = useRef(null); // To store requestAnimationFrame ID

  // Function to initiate screen capture
  const initiateAndStartCapture = async () => {
    console.log('Attempting to start screen capture...');
    if (!navigator.mediaDevices) {
      console.error('navigator.mediaDevices is not available.');
      alert('Screen capture API (mediaDevices) is not available in this browser or context.');
      onCancel();
      return;
    }
    if (typeof navigator.mediaDevices.getDisplayMedia !== 'function') {
      console.error('navigator.mediaDevices.getDisplayMedia is not a function.');
      alert('Screen capture API (getDisplayMedia) is not available or not a function. This might be due to an insecure context (non-HTTPS) or browser policy.');
      onCancel();
      return;
    }
    console.log('navigator.mediaDevices.getDisplayMedia is available.');

    try {
      const mediaStream = await navigator.mediaDevices.getDisplayMedia({
        video: { cursor: 'always' }, // Show cursor in capture
        audio: false, // No audio needed
      });
      setStream(mediaStream);

      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
        videoRef.current.onloadedmetadata = () => {
          if (canvasRef.current && videoRef.current) {
            // Set canvas dimensions to video dimensions to maintain aspect ratio
            canvasRef.current.width = videoRef.current.videoWidth;
            canvasRef.current.height = videoRef.current.videoHeight;
            
            // Start drawing video to canvas
            const drawVideoToCanvas = () => {
              if (videoRef.current && videoRef.current.srcObject && canvasRef.current && videoRef.current.readyState >= videoRef.current.HAVE_METADATA) {
                const ctx = canvasRef.current.getContext('2d');
                ctx.drawImage(videoRef.current, 0, 0, canvasRef.current.width, canvasRef.current.height);
                animationFrameId.current = requestAnimationFrame(drawVideoToCanvas);
              } else if (animationFrameId.current) {
                cancelAnimationFrame(animationFrameId.current);
              }
            };
            drawVideoToCanvas();
            setIsSelecting(true); // Enable selection mode on the canvas
          }
        };
      }
    } catch (err) {
      console.error('Error starting screen capture:', err);
      // If user cancels the browser's screen selection dialog, it's often not an error we need to alert for.
      // However, other errors (e.g., API not supported) should be handled.
      if (err.name !== 'NotAllowedError') {
        alert('Could not start screen capture. Please ensure you have granted permissions and your browser supports this feature.');
      }
      stopCaptureAndCleanup(); // Ensure cleanup if error occurs
      onCancel(); // Notify parent component
    }
  };

  // Function to stop screen capture and clean up resources
  const stopCaptureAndCleanup = () => {
    if (animationFrameId.current) {
      cancelAnimationFrame(animationFrameId.current);
      animationFrameId.current = null;
    }
    if (stream) {
      stream.getTracks().forEach(track => track.stop());
    }
    if (videoRef.current && videoRef.current.srcObject) {
      videoRef.current.srcObject.getTracks().forEach(track => track.stop());
      videoRef.current.srcObject = null;
    }
    setStream(null);
    setIsSelecting(false);
    setIsDragging(false);
    setStartPos({ x: 0, y: 0 });
    setEndPos({ x: 0, y: 0 });
    if (canvasRef.current) {
      const ctx = canvasRef.current.getContext('2d');
      ctx.clearRect(0, 0, canvasRef.current.width, canvasRef.current.height);
    }
    if (selectionRef.current) {
        selectionRef.current.style.display = 'none';
    }
  };

  // Cleanup stream on component unmount
  useEffect(() => {
    return () => {
      stopCaptureAndCleanup();
    };
  }, []);

  const handleMouseDown = (e) => {
    if (!isSelecting || !stream || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    setStartPos({ x, y });
    setEndPos({ x, y }); // Reset endPos for new selection
    setIsDragging(true);

    if (selectionRef.current) {
      selectionRef.current.style.left = `${x}px`;
      selectionRef.current.style.top = `${y}px`;
      selectionRef.current.style.width = '0px';
      selectionRef.current.style.height = '0px';
      selectionRef.current.style.display = 'block';
    }
  };

  const handleMouseMove = (e) => {
    if (!isDragging || !isSelecting || !stream || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const currentX = e.clientX - rect.left;
    const currentY = e.clientY - rect.top;
    setEndPos({ x: currentX, y: currentY });

    if (selectionRef.current) {
      const x = Math.min(startPos.x, currentX);
      const y = Math.min(startPos.y, currentY);
      const width = Math.abs(startPos.x - currentX);
      const height = Math.abs(startPos.y - currentY);
      selectionRef.current.style.left = `${x}px`;
      selectionRef.current.style.top = `${y}px`;
      selectionRef.current.style.width = `${width}px`;
      selectionRef.current.style.height = `${height}px`;
    }
  };

  const handleMouseUp = () => {
    if (!isDragging || !isSelecting || !stream) return;
    setIsDragging(false);
    // Selection is now defined by startPos and endPos
  };

  const handleCaptureScreenshotClick = () => {
    if (!videoRef.current || !canvasRef.current || !stream) {
      console.warn('Video, canvas, or stream not ready for capture.');
      return;
    }

    let sx = Math.min(startPos.x, endPos.x);
    let sy = Math.min(startPos.y, endPos.y);
    let sWidth = Math.abs(endPos.x - startPos.x);
    let sHeight = Math.abs(endPos.y - startPos.y);

    // If no drag occurred (start and end are same) or selection is too small, capture the whole canvas content
    if ((sWidth < 5 || sHeight < 5) && !(startPos.x === 0 && startPos.y === 0 && endPos.x === 0 && endPos.y === 0 && !isDragging) ) {
        // If there was an attempt to drag a tiny area, alert, otherwise assume full capture if no drag
        if (isDragging || (sWidth > 0 || sHeight > 0)) { // isDragging implies an attempt was made
             alert('Please select a larger area, or click "Capture Area" without dragging for the full view.');
             return;
        }
    }
    
    // If no selection was made (startPos and endPos are still initial or same after a click without drag), capture full canvas
    if (sWidth === 0 || sHeight === 0 || (startPos.x === endPos.x && startPos.y === endPos.y && !isDragging) ) {
      sx = 0;
      sy = 0;
      sWidth = canvasRef.current.width;
      sHeight = canvasRef.current.height;
    }

    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = sWidth;
    tempCanvas.height = sHeight;
    const tempCtx = tempCanvas.getContext('2d');

    // Draw the selected portion of the main canvas (which displays the video frame) to the temporary canvas
    tempCtx.drawImage(
      canvasRef.current, // Source is the main canvas displaying the video frame
      sx, sy, sWidth, sHeight, // Source rectangle from the main canvas
      0, 0, sWidth, sHeight    // Destination rectangle (on the tempCanvas)
    );

    const imageDataUrl = tempCanvas.toDataURL('image/png');
    stopCaptureAndCleanup();
    onScreenshotCaptured(imageDataUrl);
    // The parent component will typically close the tool by changing the state that renders it.
  };

  const handleCancelTool = () => {
    stopCaptureAndCleanup();
    onCancel();
  };

  return (
    <div className="fixed inset-0 z-[100] bg-gray-900 bg-opacity-90 backdrop-blur-md flex flex-col items-center justify-center p-1 sm:p-4">
      {!stream ? (
        <div className="bg-white p-6 sm:p-8 rounded-xl shadow-2xl text-center max-w-lg w-full">
          <CameraIcon className="mx-auto h-12 w-12 sm:h-16 sm:w-16 text-primary-600 mb-4" />
          <h3 className="text-lg sm:text-xl font-semibold text-gray-800 mb-3">Screenshot Tool</h3>
          <p className="text-xs sm:text-sm text-gray-600 mb-6 sm:mb-8">
            Click "Start Capture" to select a window, application, or your entire screen. You can then click and drag on the preview to select a specific area.
          </p>
          <div className="flex flex-col sm:flex-row justify-center space-y-3 sm:space-y-0 sm:space-x-4">
            <button
              type="button"
              onClick={initiateAndStartCapture}
              className="btn-primary w-full sm:w-auto inline-flex items-center justify-center text-sm sm:text-base px-5 py-2.5 sm:px-6 sm:py-3"
            >
              <CameraIcon className="h-5 w-5 mr-2" />
              Start Capture
            </button>
            <button
              type="button"
              onClick={handleCancelTool}
              className="btn-secondary w-full sm:w-auto inline-flex items-center justify-center text-sm sm:text-base px-5 py-2.5 sm:px-6 sm:py-3"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="w-full h-full flex flex-col bg-gray-800 rounded-lg overflow-hidden shadow-2xl border border-gray-700">
          <div className="p-3 bg-gray-700 text-white flex flex-wrap justify-between items-center border-b border-gray-600 gap-2">
            <h2 className="text-sm sm:text-md font-semibold whitespace-nowrap">Select Area to Capture</h2>
            <div className="flex space-x-2 sm:space-x-3">
              <button
                onClick={handleCaptureScreenshotClick}
                className="btn-success inline-flex items-center text-xs sm:text-sm px-3 py-1.5 sm:px-4 sm:py-2"
              >
                <ArrowUpOnSquareIcon className="h-4 sm:h-5 w-4 sm:w-5 mr-1 sm:mr-2" />
                Capture Area
              </button>
              <button
                onClick={handleCancelTool}
                className="btn-danger inline-flex items-center text-xs sm:text-sm px-3 py-1.5 sm:px-4 sm:py-2"
              >
                <StopIcon className="h-4 sm:h-5 w-4 sm:w-5 mr-1 sm:mr-2" />
                Cancel
              </button>
            </div>
          </div>

          <div className="relative flex-1 flex items-center justify-center overflow-hidden bg-black p-1">
            {/* Video element - hidden but provides the stream for the canvas */}
            <video
              ref={videoRef}
              autoPlay
              playsInline
              className="absolute opacity-0 pointer-events-none -z-10 max-w-full max-h-full"
            />
            {/* Canvas for drawing the video frame and handling mouse selection */}
            <canvas
              ref={canvasRef}
              className="object-contain cursor-crosshair max-w-full max-h-full shadow-lg"
              style={{ display: isSelecting ? 'block' : 'none' }}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
            />
            {/* Visual selection rectangle drawn over the canvas */}
            {isSelecting && (
              <div
                ref={selectionRef}
                className="absolute border-2 border-blue-400 bg-blue-500 bg-opacity-20 pointer-events-none"
                style={{ display: 'none' }} // Controlled by mouse events
              />
            )}
          </div>
          
          {isSelecting && (
            <div className="p-2 bg-gray-700 text-white text-center text-xs sm:text-sm border-t border-gray-600">
              Click and drag on the preview to select an area, or click "Capture Area" for the full view.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ScreenshotTool;
