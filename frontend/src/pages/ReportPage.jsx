import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';
import { motion } from 'framer-motion';
import {
  ArrowPathIcon,
  ExclamationTriangleIcon,
  DocumentArrowDownIcon,
  ArrowLeftIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

export default function ReportPage() {
  const { reportId } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(false);

  // Fetch report data
  useEffect(() => {
    const fetchReport = async () => {
      try {
        const response = await axios.get(`/tools/takedowniq/api/report/${reportId}`);
        setReport(response.data);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching report:', err);
        setError(err.response?.data?.detail || 'Failed to load report data');
        setLoading(false);
      }
    };

    fetchReport();
  }, [reportId]);

  // Download PDF report
  const handleDownloadReport = async () => {
    setDownloading(true);
    
    try {
      const response = await axios.get(`/tools/takedowniq/api/report/${reportId}/download`, {
        responseType: 'blob'
      });
      
      // Create a download link and trigger it
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `TakedownIQ-Report-${report.domain}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      setDownloading(false);
    } catch (err) {
      console.error('Error downloading report:', err);
      setError('Failed to download report. Please try again.');
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <ArrowPathIcon className="h-8 w-8 text-primary-600 animate-spin" />
        <span className="ml-2 text-lg text-gray-700">Loading report...</span>
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
    <div className="mx-auto max-w-4xl">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        {/* Header */}
        <div className="border-b border-gray-200 pb-5 mb-6">
          <div className="flex flex-wrap items-baseline justify-between">
            <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl">
              Report Ready: {report.domain}
            </h1>
            <div className="mt-1 flex flex-col sm:mt-0">
              <span className="inline-flex items-center rounded-md bg-green-50 px-2 py-1 text-xs font-medium text-green-700 ring-1 ring-inset ring-green-600/20">
                Report Generated
              </span>
            </div>
          </div>
          <div className="mt-1 flex flex-col sm:flex-row sm:flex-wrap sm:space-x-6">
            <div className="mt-2 flex items-center text-sm text-gray-500">
              <DocumentTextIcon className="mr-1.5 h-5 w-5 flex-shrink-0 text-gray-400" />
              Report ID: {reportId}
            </div>
          </div>
        </div>

        {/* Report preview */}
        <div className="card mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Report Preview</h2>
            <button
              onClick={handleDownloadReport}
              className="btn-primary"
              disabled={downloading}
            >
              {downloading ? (
                <>
                  <ArrowPathIcon className="h-5 w-5 mr-2 animate-spin" />
                  Downloading...
                </>
              ) : (
                <>
                  <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
                  Download PDF
                </>
              )}
            </button>
          </div>
          
          <div className="bg-gray-100 rounded-lg p-6 border border-gray-300">
            <div className="bg-white rounded-lg shadow-sm p-8 max-h-[600px] overflow-y-auto">
              {/* Report header */}
              <div className="text-center mb-8">
                <h1 className="text-2xl font-bold text-gray-900">TakedownIQ Analysis Report</h1>
                <p className="text-gray-600 mt-2">Domain: {report.domain}</p>
                <p className="text-gray-500 text-sm mt-1">
                  Generated on {new Date(report.timestamp).toLocaleString()}
                </p>
              </div>
              
              {/* Risk score */}
              <div className="mb-8">
                <h2 className="text-lg font-semibold border-b pb-2 mb-4">Risk Assessment</h2>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Risk Score:</span>
                  <span className={`font-bold ${
                    report.risk_score >= 80 ? 'text-red-600' : 
                    report.risk_score >= 50 ? 'text-yellow-600' : 
                    report.risk_score >= 20 ? 'text-blue-600' : 
                    'text-green-600'
                  }`}>
                    {report.risk_score}/100
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2.5 mb-4">
                  <div
                    className={`h-2.5 rounded-full ${
                      report.risk_score >= 80 ? 'bg-red-600' : 
                      report.risk_score >= 50 ? 'bg-yellow-500' : 
                      report.risk_score >= 20 ? 'bg-blue-500' : 
                      'bg-green-500'
                    }`}
                    style={{ width: `${report.risk_score}%` }}
                  ></div>
                </div>
                
                {report.risk_factors && report.risk_factors.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium mb-2">Risk Factors:</h3>
                    <ul className="list-disc pl-5 text-sm text-gray-600 space-y-1">
                      {report.risk_factors.map((factor, index) => (
                        <li key={index}>{factor}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
              
              {/* Domain info */}
              <div className="mb-8">
                <h2 className="text-lg font-semibold border-b pb-2 mb-4">Domain Information</h2>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="font-medium">Registration Date:</p>
                    <p className="text-gray-600">{report.whois?.creation_date || 'Unknown'}</p>
                  </div>
                  <div>
                    <p className="font-medium">Expiration Date:</p>
                    <p className="text-gray-600">{report.whois?.expiration_date || 'Unknown'}</p>
                  </div>
                  <div>
                    <p className="font-medium">Registrar:</p>
                    <p className="text-gray-600">{report.whois?.registrar || 'Unknown'}</p>
                  </div>
                  <div>
                    <p className="font-medium">WHOIS Privacy:</p>
                    <p className="text-gray-600">{report.whois?.privacy ? 'Enabled' : 'Disabled'}</p>
                  </div>
                </div>
              </div>
              
              {/* Evidence preview */}
              <div className="mb-8">
                <h2 className="text-lg font-semibold border-b pb-2 mb-4">Evidence</h2>
                {report.evidence_url ? (
                  <div className="bg-gray-50 rounded-md p-2 border border-gray-200">
                    <img
                      src={report.evidence_url}
                      alt="Evidence"
                      className="w-full h-auto object-contain max-h-[300px]"
                    />
                  </div>
                ) : (
                  <p className="text-gray-600 text-sm">No visual evidence available</p>
                )}
              </div>
              
              {/* Footer */}
              <div className="text-center text-xs text-gray-500 mt-12 pt-4 border-t">
                <p>This report was generated by TakedownIQ for investigation purposes.</p>
                <p>All data is processed in-memory and not stored after the session ends.</p>
              </div>
            </div>
          </div>
          
          <div className="mt-4 text-sm text-gray-500">
            <p>
              <strong>Note:</strong> This is a simplified preview. The PDF report contains additional details including:
            </p>
            <ul className="list-disc pl-5 mt-2">
              <li>Complete DNS records</li>
              <li>SSL certificate details</li>
              <li>VirusTotal detection results</li>
              <li>Forensic timeline</li>
              <li>Full-resolution evidence</li>
            </ul>
          </div>
        </div>
        
        {/* Actions */}
        <div className="flex justify-between">
          <Link to={`/analysis/${report.upload_id}`} className="btn-secondary">
            <ArrowLeftIcon className="h-5 w-5 mr-2" />
            Back to Analysis
          </Link>
          <button
            onClick={handleDownloadReport}
            className="btn-primary"
            disabled={downloading}
          >
            {downloading ? (
              <>
                <ArrowPathIcon className="h-5 w-5 mr-2 animate-spin" />
                Downloading...
              </>
            ) : (
              <>
                <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
                Download PDF
              </>
            )}
          </button>
        </div>
        
        {/* Security notice */}
        <div className="mt-8 bg-blue-50 rounded-md p-4 text-sm text-blue-700">
          <p className="font-medium">Security Notice:</p>
          <p className="mt-1">
            All data and evidence are stored in memory only and will be automatically wiped when your session ends.
            Please download the PDF report if you need to preserve this information.
          </p>
        </div>
      </motion.div>
    </div>
  );
}
