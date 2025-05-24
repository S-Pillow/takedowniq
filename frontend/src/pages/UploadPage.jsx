import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { motion } from 'framer-motion';
import { useDropzone } from 'react-dropzone';
import {
  ArrowPathIcon,
  ArrowUpTrayIcon,
  DocumentTextIcon,
  XMarkIcon,
  CameraIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';


export default function UploadPage() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [domain, setDomain] = useState('');
  const [notes, setNotes] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);

  const formRef = useRef(null);

  // Handle file drop
  const onDrop = (acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      const selectedFile = acceptedFiles[0];
      const fileName = selectedFile.name.toLowerCase();
      const fileType = selectedFile.type.toLowerCase();

      // Check for JPG/JPEG and PNG files by extension or MIME type
      if (!(fileName.endsWith('.jpg') || fileName.endsWith('.jpeg') || fileName.endsWith('.png') || 
            fileType === 'image/jpeg' || fileType === 'image/png')) {
        setUploadError('Only JPG and PNG files are allowed.'); 
        setFile(null); 
        setFilePreview(null);
        return; 
      }
      setUploadError(null); // Clear any previous error if the file is valid

      setFile(selectedFile);
      
      // Create preview for image files
      const reader = new FileReader();
      reader.onload = () => {
        setFilePreview(reader.result);
      };
      reader.readAsDataURL(selectedFile);
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/png': ['.png']
    },
    maxSize: 10 * 1024 * 1024, // 10MB
    maxFiles: 1
  });

  // Handle removing the file
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
      
      // Use a longer timeout for large files
      const timeout = 60000; // 60 seconds
      
      let uploadResponse;
      
      try {
        // First try the proxy endpoint
        console.log('Trying proxy endpoint: /tools/takedowniq/api/upload');
        uploadResponse = await axios.post('/tools/takedowniq/api/upload', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
          timeout
        });
      } catch (proxyErr) {
        console.error('Proxy endpoint failed:', proxyErr);
        
        try {
          // If proxy fails, try direct endpoint
          console.log('Trying direct endpoint: http://69.62.66.176:12345/upload');
          uploadResponse = await axios.post('http://69.62.66.176:12345/upload', formData, {
            headers: {
              'Content-Type': 'multipart/form-data',
            },
            timeout
          });
        } catch (directErr) {
          console.error('Direct endpoint failed:', directErr);
          
          try {
            // If direct endpoint fails, try another fallback
            console.log('Trying fallback endpoint');
            uploadResponse = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/upload`, formData, {
              headers: {
                'Content-Type': 'multipart/form-data',
              },
              timeout
            });
          } catch (fallbackErr) {
            console.error('Fallback endpoint failed:', fallbackErr);
            // If all attempts fail, throw the last error
            throw fallbackErr;
          }
        }
      }
      
      console.log('Upload successful:', uploadResponse.data);
      
      // Check if we have a valid response with upload_id
      if (uploadResponse.data && uploadResponse.data.upload_id) {
        // Navigate to the analysis page
        navigate(`/analysis/${uploadResponse.data.upload_id}`);
      } else {
        throw new Error('Invalid response from server: missing upload_id');
      }
    } catch (error) {
      console.error('Upload error:', error);
      
      // Handle different error types
      if (error.message === 'Network Error') {
        setUploadError('Network error. Please check your connection and try again. Make sure the backend server is running.');
      } else if (error.response) {
        // Server responded with an error status code
        const errorMessage = error.response.data?.detail || `Server error: ${error.response.status}`;
        setUploadError(errorMessage);
      } else if (error.request) {
        // Request was made but no response received
        setUploadError('No response from server. The server might be down or unreachable.');
      } else {
        // Something else went wrong
        setUploadError(`Error: ${error.message}`);
      }
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <form ref={formRef} onSubmit={handleSubmit} className="space-y-6">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Domain Analysis</h2>
            <p className="mt-1 text-sm text-gray-500">
              Enter a domain name and upload evidence to analyze potential security threats.
            </p>
          </div>

          {/* Domain input */}
          <div>
            <label htmlFor="domain" className="block text-sm font-medium leading-6 text-gray-900">
              Domain Name
            </label>
            <div className="mt-2">
              <input
                type="text"
                id="domain"
                name="domain"
                className="input-field"
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
              />
            </div>
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
                        <span onClick={(e) => e.stopPropagation()}>Upload a file</span>
                        <input {...getInputProps()} id="file-upload" className="sr-only" />
                      </label>
                      <p className="pl-1">or drag and drop</p>
                    </div>
                    <p className="text-xs leading-5 text-gray-600">
                      Only JPG and PNG files, up to 10MB
                    </p>
                  </div>
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
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
              <div className="flex items-start">
                <div className="flex-shrink-0">
                  <ExclamationTriangleIcon className="h-5 w-5 text-red-400" aria-hidden="true" />
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Upload Error</h3>
                  <div className="mt-2 text-sm text-red-700">
                    <p>{uploadError}</p>
                    {uploadError.includes('Network error') && (
                      <ul className="list-disc pl-5 mt-2 space-y-1 text-xs">
                        <li>Check your internet connection</li>
                        <li>The server might be temporarily unavailable</li>
                        <li>Try refreshing the page and uploading again</li>
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}



          <div className="mt-6">
            <button
              type="submit"
              className="w-full btn-primary"
              disabled={isUploading}
            >
              {isUploading ? (
                <>
                  <ArrowPathIcon className="h-5 w-5 mr-2 animate-spin" />
                  Uploading...
                </>
              ) : (
                <>
                  <ArrowUpTrayIcon className="h-5 w-5 mr-2" />
                  Upload and Analyze
                </>
              )}
            </button>
          </div>
        </form>
      </motion.div>


    </div>
  );
}
