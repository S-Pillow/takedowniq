import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { motion } from 'framer-motion';
import {
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentArrowDownIcon,
  GlobeAltIcon,
  ShieldExclamationIcon,
  CalendarIcon,
  ServerIcon,
  LockClosedIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

// Risk level badge component
const RiskBadge = ({ score }) => {
  let color, label;
  
  if (score >= 80) {
    color = 'red';
    label = 'High Risk';
  } else if (score >= 50) {
    color = 'yellow';
    label = 'Medium Risk';
  } else if (score >= 20) {
    color = 'blue';
    label = 'Low Risk';
  } else {
    color = 'green';
    label = 'Minimal Risk';
  }
  
  return (
    <span className={`badge badge-${color}`}>
      {label} ({score}/100)
    </span>
  );
};

export default function AnalysisPage() {
  // ChatGPT impact analysis state
  const [impact, setImpact] = useState(null);
  const [impactLoading, setImpactLoading] = useState(false);
  const [impactError, setImpactError] = useState(null);

  const { uploadId } = useParams();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [chatgptAnalysis, setChatgptAnalysis] = useState(null);
  const [loadingChatgpt, setLoadingChatgpt] = useState(false);
  const [chatgptError, setChatgptError] = useState(null);

  // Fetch analysis data
  useEffect(() => {
    const fetchAnalysis = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Check if this is a mock upload ID
        if (uploadId.startsWith('mock-')) {
          // Get mock data from localStorage
          const mockData = localStorage.getItem(`analysis_${uploadId}`);
          if (mockData) {
            setAnalysis(JSON.parse(mockData));
            console.log('Using mock data for analysis:', uploadId);
          } else {
            throw new Error('Mock data not found');
          }
        } else {
          // Try to get real data from the API
          const response = await axios.get(`/tools/takedowniq/api/analysis/${uploadId}`);
          setAnalysis(response.data);
        }
      } catch (error) {
        console.error('Error fetching analysis:', error);
        setError('Failed to load analysis data. Please try again.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchAnalysis();
  }, [uploadId]);

  const fetchChatGPTImpact = async () => {
    try {
      setChatgptError(null);
      setChatgptAnalysis(null);
      if (!analysis) return;
      setLoadingChatgpt(true);
      
      // Prepare data for ChatGPT analysis (ensure all required fields are present)
      const data = {
        domain: analysis.domain || '',
        risk_score: analysis.risk_score || 0,
        whois_data: analysis.whois_data || {},
        dns_data: analysis.dns_data || {},
        ssl_data: analysis.ssl_data || {},
        virustotal_data: analysis.virustotal_data || {}
      };
      
      // If using mock data, simulate a response
      if (analysis.isMock) {
        setTimeout(() => {
          setChatgptAnalysis({
            summary: "This is a mock domain summary for demonstration purposes.",
            disruption_impact_score: 7,
            news_impact_score: 5,
            rationale: "This is a mock rationale for demonstration. The domain would cause moderate disruption if placed on hold status."
          });
          setLoadingChatgpt(false);
        }, 1000);
        return;
      }
      
      // Use port 12345 where the backend is actually running
      const backendUrl = import.meta.env.VITE_API_BASE_URL.replace(':8025', ':12345');
      console.log(`Sending ChatGPT impact request to: ${backendUrl}/api/chatgpt-impact`);
      
      const response = await axios.post(`${backendUrl}/api/chatgpt-impact`, data, {
        timeout: 60000, // 60 second timeout (AI responses can take time)
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      // Check if the response contains an error
      if (response.data && response.data.error) {
        setChatgptError(response.data.error);
        setChatgptAnalysis(null);
        console.error('Error in ChatGPT analysis response:', response.data.error);
        return;
      }
      
      // Validate the response has the expected structure
      const requiredResponseFields = ['summary', 'disruption_impact_score', 'news_impact_score', 'rationale'];
      const missingResponseFields = requiredResponseFields.filter(field => !response.data[field]);
      
      if (missingResponseFields.length > 0) {
        console.warn('ChatGPT response missing some fields:', missingResponseFields);
        // We'll still set the analysis but log the warning
      }
      
      setChatgptAnalysis(response.data);
    } catch (err) {
      // Handle different types of errors
      if (err.response) {
        // The request was made and the server responded with a status code outside the 2xx range
        const statusCode = err.response.status;
        const errorData = err.response.data;
        
        if (statusCode === 400) {
          setChatgptError(`Bad request: ${errorData.error || 'Invalid data provided'}`);
        } else if (statusCode === 401 || statusCode === 403) {
          setChatgptError('Authentication error with the AI service');
        } else if (statusCode === 429) {
          setChatgptError('AI service rate limit exceeded. Please try again later.');
        } else if (statusCode >= 500) {
          setChatgptError('AI service is currently unavailable. Please try again later.');
        } else {
          setChatgptError(`Error: ${errorData.error || err.message || 'Unknown error'}`);
        }
      } else if (err.request) {
        // The request was made but no response was received
        setChatgptError('No response from the server. Please check your network connection.');
      } else if (err.message && err.message.includes('timeout')) {
        // Request timed out
        setChatgptError('Request timed out. The AI analysis is taking longer than expected.');
      } else {
        // Something else happened while setting up the request
        setChatgptError(`Failed to fetch ChatGPT analysis: ${err.message || 'Unknown error'}`);
      }
      
      setChatgptAnalysis(null);
      console.error('Error fetching ChatGPT impact analysis:', err);
    } finally {
      setLoadingChatgpt(false);
    }
  };

  // Add a button to manually trigger ChatGPT analysis
  const handleGenerateChatGPTAnalysis = () => {
    fetchChatGPTImpact();
  };
  
  // Don't auto-fetch ChatGPT analysis on load to avoid unnecessary API calls

  // Generate PDF report
  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    
    try {
      // For mock data, simulate report generation
      if (uploadId.startsWith('mock-')) {
        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Create a mock report ID
        const mockReportId = 'mock-report-' + Math.random().toString(36).substring(2, 10);
        
        // Store mock report data in localStorage
        const mockReportData = {
          report_id: mockReportId,
          upload_id: uploadId,
          domain: analysis.domain,
          timestamp: new Date().toISOString(),
          status: 'completed',
          download_url: '#'
        };
        
        localStorage.setItem(`report_${mockReportId}`, JSON.stringify(mockReportData));
        
        // Navigate to the report page
        navigate(`/report/${mockReportId}`);
      } else {
        // For real data, make the actual API call
        const response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/report/${uploadId}`);
        navigate(`/report/${response.data.report_id}`);
      }
    } catch (err) {
      console.error('Error generating report:', err);
      setError('Failed to generate report. Please try again.');
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <ArrowPathIcon className="h-8 w-8 text-primary-600 animate-spin" />
        <span className="ml-2 text-lg text-gray-700">Analyzing domain...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-md bg-red-50 p-4 max-w-3xl mx-auto mt-8">
        <div className="flex">
          <ExclamationTriangleIcon className="h-5 w-5 text-red-400" aria-hidden="true" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error</h3>
            <div className="mt-2 text-sm text-red-700">
              <p>{error}</p>
            </div>
            <div className="mt-4">
              <Link to="/upload" className="btn-secondary text-sm">
                Return to Upload
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        {/* Header */}
        <div className="border-b border-gray-200 pb-5 mb-6">
          <div className="flex flex-wrap items-baseline">
            <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl">
              Analysis Results: {analysis.domain}
            </h1>
            <div className="mt-1 flex flex-col sm:mt-0 sm:ml-4">
              <RiskBadge score={analysis.risk_score} />
            </div>
          </div>
          <div className="mt-1 flex flex-col sm:flex-row sm:flex-wrap sm:space-x-6">
            <div className="mt-2 flex items-center text-sm text-gray-500">
              <CalendarIcon className="mr-1.5 h-5 w-5 flex-shrink-0 text-gray-400" />
              Analyzed on {new Date(analysis.timestamp).toLocaleString()}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Main content - left 2/3 */}
          <div className="md:col-span-2 space-y-6">
            {/* Domain Info */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Domain Information</h2>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Registration Date</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.creation_date || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Expiration Date</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.expiration_date || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Domain Age</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.domain_age || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Registrar</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.registrar || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Domain Status</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {Array.isArray(analysis.whois_data?.status) ? (
                      <ul className="list-none space-y-1">
                        {analysis.whois_data.status.map((status, index) => (
                          <li key={`status-${index}`} className="font-mono">{status}</li>
                        ))}
                      </ul>
                    ) : typeof analysis.whois_data?.status === 'string' ? (
                      <ul className="list-none space-y-1">
                        <li className="font-mono">{analysis.whois_data.status}</li>
                      </ul>
                    ) : (
                      'Unknown'
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Name Servers</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {Array.isArray(analysis.dns_data?.ns_records) && analysis.dns_data.ns_records.length > 0 ? (
                      <ul className="list-none space-y-1">
                        {analysis.dns_data.ns_records.map((ns, index) => (
                          <li key={`ns-${index}`} className="font-mono">{ns}</li>
                        ))}
                      </ul>
                    ) : (
                      'Unknown'
                    )}
                  </dd>
                </div>
              </dl>
            </div>

            {/* VirusTotal Results */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <span>VirusTotal Results</span>
                {analysis.virustotal_data && analysis.virustotal_data.malicious_count > 0 && (
                  <span className="ml-2 badge badge-red">Threats Detected</span>
                )}
              </h2>
              
              {analysis.virustotal_data ? (
                <div className="space-y-4">
                  {/* Analysis Stats */}
                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                    <div className={`bg-gray-50 rounded-lg p-4 text-center ${analysis.virustotal_data.malicious_count > 0 ? 'border-l-4 border-red-500' : ''}`}>
                      <dt className="text-sm font-medium text-gray-500">Malicious</dt>
                      <dd className="mt-1 text-2xl font-semibold text-red-600">
                        {analysis.virustotal_data.malicious_count}
                      </dd>
                    </div>
                    <div className={`bg-gray-50 rounded-lg p-4 text-center ${analysis.virustotal_data.suspicious_count > 0 ? 'border-l-4 border-yellow-500' : ''}`}>
                      <dt className="text-sm font-medium text-gray-500">Suspicious</dt>
                      <dd className="mt-1 text-2xl font-semibold text-yellow-600">
                        {analysis.virustotal_data.suspicious_count}
                      </dd>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-4 text-center border-l-4 border-green-500">
                      <dt className="text-sm font-medium text-gray-500">Harmless</dt>
                      <dd className="mt-1 text-2xl font-semibold text-green-600">
                        {analysis.virustotal_data.harmless_count}
                      </dd>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-4 text-center">
                      <dt className="text-sm font-medium text-gray-500">Total Engines</dt>
                      <dd className="mt-1 text-2xl font-semibold text-gray-900">
                        {analysis.virustotal_data.total_engines}
                      </dd>
                    </div>
                  </div>
                  
                  {/* Detection Progress Bar */}
                  <div className="mb-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-gray-700">Detection Rate</span>
                      <span className="text-sm font-medium text-gray-700">
                        {analysis.virustotal_data.malicious_count + analysis.virustotal_data.suspicious_count}/{analysis.virustotal_data.total_engines}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2.5 overflow-hidden">
                      <div className="flex h-full">
                        <div 
                          className="bg-red-600 h-full" 
                          style={{ width: `${(analysis.virustotal_data.malicious_count / analysis.virustotal_data.total_engines) * 100}%` }}
                        ></div>
                        <div 
                          className="bg-yellow-500 h-full" 
                          style={{ width: `${(analysis.virustotal_data.suspicious_count / analysis.virustotal_data.total_engines) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Last Analysis Date */}
                  {analysis.virustotal_data.last_analysis_date && (
                    <div className="text-sm text-gray-600 mb-4 border-t border-b border-gray-100 py-2">
                      <strong>Last scanned:</strong> {new Date(analysis.virustotal_data.last_analysis_date * 1000).toLocaleString()}
                    </div>
                  )}
                  
                  {/* Detections */}
                  {analysis.virustotal_data.detections && analysis.virustotal_data.detections.length > 0 && (
                    <div>
                      <h3 className="text-lg font-medium text-gray-800 mb-3">Detection Details</h3>
                      <div className="overflow-x-auto border rounded-lg">
                        <table className="min-w-full divide-y divide-gray-200">
                          <thead className="bg-gray-100">
                            <tr>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-600 uppercase tracking-wider">ENGINE</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-600 uppercase tracking-wider">CATEGORY</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-600 uppercase tracking-wider">RESULT</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {analysis.virustotal_data.detections.map((detection, index) => (
                              <tr key={index} className={detection.category === 'malicious' ? 'bg-red-50' : detection.category === 'suspicious' ? 'bg-yellow-50' : 'bg-white'}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{detection.engine}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm">
                                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${detection.category === 'malicious' ? 'bg-red-100 text-red-800' : detection.category === 'suspicious' ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
                                    {detection.category}
                                  </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-600">{detection.result}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No VirusTotal data available</p>
              )}
            </div>
          </div>

          {/* Sidebar - right 1/3 */}
          <div className="space-y-6">
            {/* Risk Assessment */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Risk Assessment</h2>
              <div className="mb-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-700">Risk Score</span>
                  <span className="text-sm font-medium text-gray-700">{analysis.risk_score}/100</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2.5">
                  <div 
                    className={`h-2.5 rounded-full ${
                      analysis.risk_score >= 80 ? 'bg-red-600' : 
                      analysis.risk_score >= 50 ? 'bg-yellow-500' : 
                      analysis.risk_score >= 20 ? 'bg-blue-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${analysis.risk_score}%` }}
                  ></div>
                </div>
              </div>
              
              {/* Risk Factors */}
              {analysis.risk_factors && analysis.risk_factors.length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-2">Risk Factors</h3>
                  <ul className="space-y-1">
                    {analysis.risk_factors.map((factor, index) => (
                      <li key={index} className="flex items-start">
                        <ShieldExclamationIcon className="h-5 w-5 text-red-500 mr-2 flex-shrink-0" />
                        <span className="text-sm text-gray-700">
                          {typeof factor === 'string' ? factor : 
                           factor && typeof factor === 'object' && factor.description ? 
                           factor.description : 
                           JSON.stringify(factor)}
                        </span>
                      </li>
                    ))}

                  </ul>
                </div>
              )}
            </div>
            
            {/* ChatGPT Impact Analysis */}
            <div className="card mb-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <span>ChatGPT Impact Analysis</span>
              </h2>
              
              {loadingChatgpt ? (
                <div className="flex items-center justify-center py-4">
                  <ArrowPathIcon className="h-5 w-5 text-primary-600 animate-spin mr-2" />
                  <span>Generating AI analysis...</span>
                </div>
              ) : chatgptError ? (
                <div className="py-4 border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start mb-3">
                    <ExclamationTriangleIcon className="h-5 w-5 text-amber-500 mr-2 flex-shrink-0" />
                    <div>
                      <h3 className="text-sm font-medium text-gray-900">AI Analysis Unavailable</h3>
                      <p className="text-sm text-gray-600 mt-1">The ChatGPT impact analysis is currently unavailable. This may be due to API configuration issues.</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mb-3">Error details: {chatgptError}</p>
                  <div className="flex justify-between items-center">
                    <button
                      onClick={fetchChatGPTImpact}
                      className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                    >
                      <ArrowPathIcon className="h-4 w-4 mr-1" />
                      Retry Analysis
                    </button>
                    <span className="text-xs text-gray-500">You can continue using other features while this is unavailable.</span>
                  </div>
                </div>
              ) : chatgptAnalysis ? (
                <div className="space-y-4">
                  {chatgptAnalysis.summary && (
                    <div className="bg-blue-50 p-3 rounded-lg border border-blue-100">
                      <span className="font-medium text-blue-800">Summary:</span>
                      <div className="text-sm text-blue-700 mt-1">{chatgptAnalysis.summary}</div>
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
                      <div className="text-center mb-1 text-gray-600 text-xs uppercase font-semibold">Disruption Impact</div>
                      <div className="flex justify-center">
                        <span className={`text-2xl font-bold ${chatgptAnalysis.disruption_impact_score >= 7 ? 'text-red-600' : chatgptAnalysis.disruption_impact_score >= 4 ? 'text-yellow-600' : 'text-blue-600'}`}>
                          {chatgptAnalysis.disruption_impact_score ?? 'N/A'}
                        </span>
                        <span className="text-sm text-gray-500 self-end ml-1">/10</span>
                      </div>
                    </div>
                    
                    <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
                      <div className="text-center mb-1 text-gray-600 text-xs uppercase font-semibold">News Impact</div>
                      <div className="flex justify-center">
                        <span className={`text-2xl font-bold ${chatgptAnalysis.news_impact_score >= 7 ? 'text-purple-600' : chatgptAnalysis.news_impact_score >= 4 ? 'text-indigo-600' : 'text-gray-600'}`}>
                          {chatgptAnalysis.news_impact_score ?? 'N/A'}
                        </span>
                        <span className="text-sm text-gray-500 self-end ml-1">/10</span>
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <span className="font-medium">Analysis:</span>
                    <div className="text-sm text-gray-700 whitespace-pre-line mt-2 bg-white p-3 rounded-lg border border-gray-200">{chatgptAnalysis.rationale}</div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-4">
                  <p className="text-gray-500">AI analysis not available</p>
                  <button
                    onClick={fetchChatGPTImpact}
                    className="mt-2 inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    Generate Analysis
                  </button>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Actions</h2>
              <div className="space-y-4">
                <button
                  type="button"
                  onClick={handleGenerateReport}
                  disabled={generatingReport}
                  className="w-full btn-primary flex justify-center items-center"
                >
                  {generatingReport ? (
                    <>
                      <ArrowPathIcon className="h-5 w-5 mr-2 animate-spin" />
                      Generating Report...
                    </>
                  ) : (
                    <>
                      <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
                      Generate PDF Report
                    </>
                  )}
                </button>
                
                <Link to="/upload" className="w-full btn-secondary flex justify-center items-center">
                  <GlobeAltIcon className="h-5 w-5 mr-2" />
                  Analyze Another Domain
                </Link>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
