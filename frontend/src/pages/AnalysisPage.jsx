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


  // Fetch analysis data
  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const response = await axios.get(`/tools/takedowniq/api/analysis/${uploadId}`);
        setAnalysis(response.data);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching analysis:', err);
        setError(err.response?.data?.detail || 'Failed to load analysis data');
        setLoading(false);
      }
    };

    fetchAnalysis();
  }, [uploadId]);

  // Fetch ChatGPT impact analysis after main analysis loads
  useEffect(() => {
    if (!analysis) return;
    const fetchImpact = async () => {
      setImpactLoading(true);
      setImpactError(null);
      try {
        // Only send relevant fields to backend
        const payload = {
          domain: analysis.domain,
          whois_data: analysis.whois_data || analysis.whois || {},
          dns_data: analysis.dns_data || analysis.dns || {},
          ssl_data: analysis.ssl_data || analysis.ssl || {},
          virustotal_data: analysis.virustotal_data || analysis.virustotal || {},
        };
        const response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/chatgpt-impact`, payload);
        setImpact(response.data);
      } catch (err) {
        setImpactError(err.response?.data?.error || 'Failed to load impact analysis');
      } finally {
        setImpactLoading(false);
      }
    };
    fetchImpact();
  }, [analysis]);

  // Generate PDF report
  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    
    try {
      const response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/report/${uploadId}`);
      navigate(`/report/${response.data.report_id}`);
    } catch (err) {
      console.error('Error generating report:', err);
      setError(err.response?.data?.detail || 'Failed to generate report');
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
                    {analysis.whois?.creation_date || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Expiration Date</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois?.expiration_date || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Registrar</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois?.registrar || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">WHOIS Privacy</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois?.privacy ? 'Enabled' : 'Disabled'}
                  </dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-sm font-medium text-gray-500">Name Servers</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.dns?.nameservers?.length > 0 ? (
                      <ul className="list-disc pl-5">
                        {analysis.dns.nameservers.map((ns, index) => (
                          <li key={index}>{ns}</li>
                        ))}
                      </ul>
                    ) : (
                      'None found'
                    )}
                  </dd>
                </div>
              </dl>
            </div>

            {/* DNS Records */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">DNS Records</h2>
              {analysis.dns?.records?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-300">
                    <thead>
                      <tr>
                        <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Type</th>
                        <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Name</th>
                        <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Value</th>
                        <th className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">TTL</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {analysis.dns.records.map((record, index) => (
                        <tr key={index}>
                          <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-900">{record.type}</td>
                          <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-900">{record.name}</td>
                          <td className="px-3 py-4 text-sm text-gray-900 break-all">{record.value}</td>
                          <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-900">{record.ttl}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No DNS records found</p>
              )}
            </div>

            {/* SSL Certificates */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">SSL Certificates</h2>
              {analysis.ssl?.certificates?.length > 0 ? (
                <div className="space-y-4">
                  {analysis.ssl.certificates.map((cert, index) => (
                    <div key={index} className="border rounded-md p-4">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2">
                        <div>
                          <dt className="text-sm font-medium text-gray-500">Issuer</dt>
                          <dd className="mt-1 text-sm text-gray-900">{cert.issuer}</dd>
                        </div>
                        <div>
                          <dt className="text-sm font-medium text-gray-500">Valid From</dt>
                          <dd className="mt-1 text-sm text-gray-900">{cert.valid_from}</dd>
                        </div>
                        <div>
                          <dt className="text-sm font-medium text-gray-500">Valid To</dt>
                          <dd className="mt-1 text-sm text-gray-900">{cert.valid_to}</dd>
                        </div>
                        <div>
                          <dt className="text-sm font-medium text-gray-500">Serial Number</dt>
                          <dd className="mt-1 text-sm text-gray-900 truncate">{cert.serial_number}</dd>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No SSL certificates found</p>
              )}
            </div>

            {/* VirusTotal Results */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">VirusTotal Results</h2>
              {analysis.virustotal ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-gray-50 rounded-lg p-4 text-center">
                      <dt className="text-sm font-medium text-gray-500">Malicious Detections</dt>
                      <dd className="mt-1 text-2xl font-semibold text-danger-600">
                        {analysis.virustotal.malicious_count}
                      </dd>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-4 text-center">
                      <dt className="text-sm font-medium text-gray-500">Suspicious Detections</dt>
                      <dd className="mt-1 text-2xl font-semibold text-yellow-600">
                        {analysis.virustotal.suspicious_count}
                      </dd>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-4 text-center">
                      <dt className="text-sm font-medium text-gray-500">Total Engines</dt>
                      <dd className="mt-1 text-2xl font-semibold text-gray-900">
                        {analysis.virustotal.total_engines}
                      </dd>
                    </div>
                  </div>
                  
                  {analysis.virustotal.categories && Object.keys(analysis.virustotal.categories).length > 0 && (
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 mb-2">Categories</h3>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(analysis.virustotal.categories).map(([vendor, category]) => (
                          <span key={vendor} className="badge badge-gray">
                            {vendor}: {category}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No VirusTotal data available</p>
              )}
            </div>

            {/* Forensic Timeline */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Forensic Timeline</h2>
              {analysis.timeline?.length > 0 ? (
                <div className="flow-root">
                  <ul className="-mb-8">
                    {analysis.timeline.map((event, index) => (
                      <li key={index}>
                        <div className="relative pb-8">
                          {index !== analysis.timeline.length - 1 ? (
                            <span
                              className="absolute left-4 top-4 -ml-px h-full w-0.5 bg-gray-200"
                              aria-hidden="true"
                            />
                          ) : null}
                          <div className="relative flex space-x-3">
                            <div>
                              <span className="h-8 w-8 rounded-full flex items-center justify-center ring-8 ring-white bg-gray-100">
                                {event.type === 'registration' && <CalendarIcon className="h-5 w-5 text-blue-500" />}
                                {event.type === 'dns_change' && <ServerIcon className="h-5 w-5 text-green-500" />}
                                {event.type === 'ssl_issuance' && <LockClosedIcon className="h-5 w-5 text-yellow-500" />}
                                {event.type === 'detection' && <ShieldExclamationIcon className="h-5 w-5 text-red-500" />}
                              </span>
                            </div>
                            <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                              <div>
                                <p className="text-sm text-gray-900">{event.description}</p>
                              </div>
                              <div className="text-right text-sm whitespace-nowrap text-gray-500">
                                <time dateTime={event.date}>{event.date}</time>
                              </div>
                            </div>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No timeline events available</p>
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
                      analysis.risk_score >= 80
                        ? 'bg-red-600'
                        : analysis.risk_score >= 50
                        ? 'bg-yellow-500'
                        : analysis.risk_score >= 20
                        ? 'bg-blue-500'
                        : 'bg-green-500'
                    }`}
                    style={{ width: `${analysis.risk_score}%` }}
                  ></div>
                </div>
              </div>
              
              <h3 className="text-sm font-medium text-gray-700 mb-2">Risk Factors</h3>
              <ul className="space-y-2">
                {analysis.risk_factors?.map((factor, index) => (
                  <li key={index} className="flex items-start">
                    <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500 mr-2 flex-shrink-0" />
                    <span className="text-sm text-gray-600">{factor}</span>
                  </li>
                ))}
                {(!analysis.risk_factors || analysis.risk_factors.length === 0) && (
                  <li className="flex items-start">
                    <CheckCircleIcon className="h-5 w-5 text-green-500 mr-2 flex-shrink-0" />
                    <span className="text-sm text-gray-600">No significant risk factors identified</span>
                  </li>
                )}
              </ul>
            </div>

            {/* ChatGPT Impact Analysis */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <span>ChatGPT Impact Analysis</span>
                <span className="ml-2"><LockClosedIcon className="h-5 w-5 text-blue-500 inline" /></span>
              </h2>
              {impactLoading && (
                <div className="flex items-center text-sm text-gray-500"><ArrowPathIcon className="h-5 w-5 animate-spin mr-2" />Analyzing impact...</div>
              )}
              {impactError && (
                <div className="rounded bg-red-100 text-red-700 p-2 mb-2 text-sm">{impactError}</div>
              )}
              {impact && !impactError && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">Disruption Impact Score:</span>
                    <span className="badge badge-blue">{impact.disruption_impact_score ?? 'N/A'}/10</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">News Impact Score:</span>
                    <span className="badge badge-purple">{impact.news_impact_score ?? 'N/A'}/10</span>
                  </div>
                  <div>
                    <span className="font-medium">Rationale:</span>
                    <div className="text-sm text-gray-700 whitespace-pre-line">{impact.rationale}</div>
                  </div>
                  {impact.criteria && (
                    <div>
                      <span className="font-medium">Criteria:</span>
                      <ul className="list-disc pl-5 text-sm text-gray-700">
                        <li><b>Disruption:</b> {impact.criteria.disruption}</li>
                        <li><b>News:</b> {impact.criteria.news}</li>
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Evidence Preview */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Evidence Preview</h2>
              {analysis.evidence_url ? (
                <div className="bg-gray-100 rounded-md overflow-hidden">
                  <img
                    src={analysis.evidence_url}
                    alt="Evidence"
                    className="w-full h-auto object-contain"
                  />
                </div>
              ) : (
                <div className="bg-gray-100 rounded-md p-8 flex items-center justify-center">
                  <DocumentTextIcon className="h-12 w-12 text-gray-400" />
                </div>
              )}
              <p className="mt-2 text-sm text-gray-500">
                {analysis.evidence_type || 'Evidence file'} uploaded on{' '}
                {new Date(analysis.timestamp).toLocaleString()}
              </p>
            </div>

            {/* Notes */}
            {analysis.notes && (
              <div className="card">
                <h2 className="text-xl font-semibold mb-4">Investigation Notes</h2>
                <p className="text-sm text-gray-600 whitespace-pre-line">{analysis.notes}</p>
              </div>
            )}

            {/* Actions */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Actions</h2>
              <div className="space-y-4">
                <button
                  onClick={handleGenerateReport}
                  className="btn-primary w-full"
                  disabled={generatingReport}
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
                <Link to="/upload" className="btn-secondary w-full block text-center">
                  <GlobeAltIcon className="h-5 w-5 mr-2 inline-block" />
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
