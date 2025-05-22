import { useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import { motion } from 'framer-motion';
import { 
  ArrowUpTrayIcon, 
  CameraIcon, 
  DocumentTextIcon, 
  XMarkIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';
import ScreenshotTool from '../components/ScreenshotTool';

export default function UploadPage() {
  const navigate = useNavigate();
  const [domain, setDomain] = useState('');
  const [notes, setNotes] = useState('');
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [showScreenshotTool, setShowScreenshotTool] = useState(false);
  const formRef = useRef(null);

  // Handle file drop
  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      const selectedFile = acceptedFiles[0];
      setFile(selectedFile);
      
      // Create preview for image files
      if (selectedFile.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = () => {
          setFilePreview(reader.result);
        };
        reader.readAsDataURL(selectedFile);
      } else {
        setFilePreview(null);
      }
    }
  }, []);

  // Configure dropzone
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'image/*': ['.png', '.jpg', '.jpeg', '.gif'],
      'application/pdf': ['.pdf'],
      'text/plain': ['.txt', '.log'],
      'text/html': ['.html', '.htm'],
    },
    maxFiles: 1,
    maxSize: 10485760, // 10MB
  });

  // Handle screenshot capture
  const handleScreenshotCaptured = (screenshotDataUrl) => {
    setShowScreenshotTool(false);
    
    // Convert data URL to File object
    fetch(screenshotDataUrl)
      .then(res => res.blob())
      .then(blob => {
        const screenshotFile = new File([blob], 'screenshot.png', { type: 'image/png' });
        setFile(screenshotFile);
        setFilePreview(screenshotDataUrl);
      });
  };

  // Remove the current file
  const handleRemoveFile = () => {
    setFile(null);
    setFilePreview(null);
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!domain || !file) {
      setUploadError('Please provide both a domain name and upload a file');
      return;
    }
    
    setIsUploading(true);
    setUploadError(null);
    
    try {
      // Create form data
      const formData = new FormData();
      formData.append('file', file);
      formData.append('domain', domain);
      if (notes) {
        formData.append('notes', notes);
      }
      
      // Upload to the API
      const response = await axios.post('/tools/takedowniq/api/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      // Navigate to analysis page with the upload ID
      navigate(`/analysis/${response.data.upload_id}`);
    } catch (error) {
      console.error('Upload error:', error);
      setUploadError(
        error.response?.data?.detail || 
        'An error occurred during upload. Please try again.'
      );
      setIsUploading(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold tracking-tight text-gray-900">Upload Evidence</h1>
          <p className="mt-2 text-lg text-gray-600">
            Upload a screenshot or other evidence to analyze a suspicious domain
          </p>
        </div>

        <form ref={formRef} onSubmit={handleSubmit} className="space-y-8">
          {/* Domain input */}
          <div>
            <label htmlFor="domain" className="block text-sm font-medium leading-6 text-gray-900">
              Domain Name
            </label>
            <div className="mt-2">
              <input
                type="text"
                name="domain"
                id="domain"
                className="input-field"
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
              />
            </div>
            <p className="mt-1 text-sm text-gray-500">
              Enter the suspicious domain you want to analyze
            </p>
          </div>

          {/* File upload area */}
          <div>
            <label className="block text-sm font-medium leading-6 text-gray-900">
              Evidence Upload
            </label>
            
            {!file ? (
              <div className="mt-2 flex flex-col items-center">
                <div
                  {...getRootProps()}
                  className={`mt-2 flex justify-center rounded-lg border border-dashed px-6 py-10 w-full ${
                    isDragActive 
                      ? 'border-primary-500 bg-primary-50' 
                      : 'border-gray-300 hover:border-primary-400'
                  }`}
                >
                  <div className="text-center">
                    <ArrowUpTrayIcon className="mx-auto h-12 w-12 text-gray-400" />
                    <div className="mt-4 flex text-sm leading-6 text-gray-600">
                      <label
                        htmlFor="file-upload"
                        className="relative cursor-pointer rounded-md bg-white font-semibold text-primary-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-primary-600 focus-within:ring-offset-2 hover:text-primary-500"
                      >
                        <span>Upload a file</span>
                        <input {...getInputProps()} id="file-upload" className="sr-only" />
                      </label>
                      <p className="pl-1">or drag and drop</p>
                    </div>
                    <p className="text-xs leading-5 text-gray-600">
                      PNG, JPG, GIF, PDF, TXT or HTML up to 10MB
                    </p>
                  </div>
                </div>
                
                <div className="mt-4 text-center">
                  <p className="text-sm text-gray-500">Or use our built-in tool</p>
                  <button
                    type="button"
                    onClick={() => setShowScreenshotTool(true)}
                    className="mt-2 btn-secondary"
                  >
                    <CameraIcon className="h-5 w-5 mr-2" />
                    Capture Screenshot
                  </button>
                </div>
              </div>
            ) : (
              <div className="mt-2 rounded-lg border border-gray-300 bg-white p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    {filePreview ? (
                      <div className="h-16 w-16 flex-shrink-0 rounded-md overflow-hidden bg-gray-100">
                        <img
                          src={filePreview}
                          alt="Preview"
                          className="h-full w-full object-cover"
                        />
                      </div>
                    ) : (
                      <DocumentTextIcon className="h-10 w-10 flex-shrink-0 text-gray-400" />
                    )}
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-gray-900 truncate">
                        {file.name}
                      </p>
                      <p className="text-sm text-gray-500">
                        {(file.size / 1024).toFixed(2)} KB
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={handleRemoveFile}
                    className="ml-4 flex-shrink-0 rounded-md bg-white p-1 text-gray-400 hover:text-gray-500"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Notes textarea */}
          <div>
            <label htmlFor="notes" className="block text-sm font-medium leading-6 text-gray-900">
              Additional Notes
            </label>
            <div className="mt-2">
              <textarea
                id="notes"
                name="notes"
                rows={4}
                className="input-field"
                placeholder="Add any additional context or observations about this domain..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
          </div>

          {/* Error message */}
          {uploadError && (
            <div className="rounded-md bg-red-50 p-4">
              <div className="flex">
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Error</h3>
                  <div className="mt-2 text-sm text-red-700">
                    <p>{uploadError}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Submit button */}
          <div className="flex justify-end">
            <button
              type="submit"
              className="btn-primary"
              disabled={isUploading || !domain || !file}
            >
              {isUploading ? (
                <>
                  <ArrowPathIcon className="h-5 w-5 mr-2 animate-spin" />
                  Uploading...
                </>
              ) : (
                'Analyze Domain'
              )}
            </button>
          </div>
        </form>
      </motion.div>

      {/* Screenshot tool modal */}
      {showScreenshotTool && (
        <ScreenshotTool
          onScreenshotCaptured={handleScreenshotCaptured}
          onCancel={() => setShowScreenshotTool(false)}
        />
      )}
    </div>
  );
}
