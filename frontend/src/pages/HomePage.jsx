import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  ShieldCheckIcon, 
  DocumentTextIcon, 
  ClockIcon, 
  ChartBarIcon,
  MagnifyingGlassIcon,
  DocumentDuplicateIcon 
} from '@heroicons/react/24/outline';

const features = [
  {
    name: 'Safe Domain Analysis',
    description: 'Analyze suspicious domains without visiting them directly, keeping your systems protected.',
    icon: ShieldCheckIcon,
  },
  {
    name: 'Comprehensive Metadata',
    description: 'Collect WHOIS, DNS history, SSL certificates, and VirusTotal results in one place.',
    icon: MagnifyingGlassIcon,
  },
  {
    name: 'Forensic Timeline',
    description: 'Generate a detailed timeline of domain registration, DNS changes, and certificate issuance.',
    icon: ClockIcon,
  },
  {
    name: 'AI Risk Scoring',
    description: 'Get an intelligent risk assessment with detailed explanation of potential threats.',
    icon: ChartBarIcon,
  },
  {
    name: 'Professional Reports',
    description: 'Download comprehensive PDF reports for internal review or registrar escalation.',
    icon: DocumentTextIcon,
  },
  {
    name: 'Evidence Collection',
    description: 'Upload screenshots and logs as evidence without visiting suspicious sites.',
    icon: DocumentDuplicateIcon,
  },
];

export default function HomePage() {
  return (
    <div className="bg-white">
      {/* Hero section */}
      <div className="relative isolate overflow-hidden">
        <div className="mx-auto max-w-7xl px-6 pb-24 pt-10 sm:pb-32 lg:flex lg:px-8 lg:py-16">
          <div className="mx-auto max-w-2xl lg:mx-0 lg:max-w-xl lg:flex-shrink-0 lg:pt-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <div className="mt-24 sm:mt-32 lg:mt-16">
                <span className="inline-flex items-center rounded-md bg-primary-50 px-3 py-1 text-sm font-medium text-primary-700 ring-1 ring-inset ring-primary-600/20">
                  New
                </span>
              </div>
              <h1 className="mt-4 text-4xl font-bold tracking-tight text-gray-900 sm:text-6xl">
                Investigate suspicious domains safely
              </h1>
              <p className="mt-6 text-lg leading-8 text-gray-600">
                TakedownIQ helps cybersecurity professionals assess suspicious or abusive domains 
                without visiting them directly. Upload evidence, collect metadata, and generate 
                professional reports for takedown requests.
              </p>
              <div className="mt-10 flex items-center gap-x-6">
                <Link
                  to="/upload"
                  className="btn-primary text-base"
                >
                  Get started
                </Link>
                <a href="#features" className="text-base font-semibold leading-7 text-gray-900">
                  Learn more <span aria-hidden="true">→</span>
                </a>
              </div>
            </motion.div>
          </div>
          <div className="mx-auto mt-16 flex max-w-2xl sm:mt-24 lg:ml-10 lg:mr-0 lg:mt-0 lg:max-w-none lg:flex-none xl:ml-32">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="max-w-3xl flex-none sm:max-w-5xl lg:max-w-none"
            >
              <div className="-m-2 rounded-xl bg-gray-900/5 p-2 ring-1 ring-inset ring-gray-900/10 lg:-m-4 lg:rounded-2xl lg:p-4">
                <img
                  src="/tools/takedowniq/dashboard-preview.png"
                  alt="App screenshot"
                  width={2432}
                  height={1442}
                  className="w-[76rem] rounded-md shadow-2xl ring-1 ring-gray-900/10"
                  onError={(e) => {
                    e.target.onerror = null;
                    e.target.src = "https://placehold.co/800x500/e0f2fe/0284c7?text=TakedownIQ+Dashboard&font=roboto";
                  }}
                />
              </div>
            </motion.div>
          </div>
        </div>
      </div>

      {/* Features section */}
      <div id="features" className="mx-auto mt-8 max-w-7xl px-6 sm:mt-16 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-base font-semibold leading-7 text-primary-600">Powerful features</h2>
          <p className="mt-2 text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">
            Everything you need for domain investigation
          </p>
          <p className="mt-6 text-lg leading-8 text-gray-600">
            TakedownIQ provides a comprehensive set of tools for cybersecurity professionals to investigate
            suspicious domains safely and efficiently.
          </p>
        </div>
      </div>

      {/* Feature list */}
      <div className="mx-auto mt-16 max-w-7xl px-6 sm:mt-20 md:mt-24 lg:px-8">
        <dl className="mx-auto grid max-w-2xl grid-cols-1 gap-x-6 gap-y-10 text-base leading-7 text-gray-600 sm:grid-cols-2 lg:mx-0 lg:max-w-none lg:grid-cols-3 lg:gap-x-8 lg:gap-y-16">
          {features.map((feature, index) => (
            <motion.div 
              key={feature.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="relative pl-9"
            >
              <dt className="inline font-semibold text-gray-900">
                <feature.icon className="absolute left-1 top-1 h-5 w-5 text-primary-600" aria-hidden="true" />
                {feature.name}
              </dt>{' '}
              <dd className="inline">{feature.description}</dd>
            </motion.div>
          ))}
        </dl>
      </div>

      {/* CTA section */}
      <div className="mx-auto mt-32 max-w-7xl sm:mt-40 sm:px-6 lg:px-8">
        <div className="relative isolate overflow-hidden bg-primary-700 px-6 py-24 text-center shadow-2xl sm:rounded-3xl sm:px-16">
          <h2 className="mx-auto max-w-2xl text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Start investigating suspicious domains today
          </h2>
          <p className="mx-auto mt-6 max-w-xl text-lg leading-8 text-gray-100">
            Upload evidence, collect metadata, and generate professional reports for takedown requests.
          </p>
          <div className="mt-10 flex items-center justify-center gap-x-6">
            <Link
              to="/upload"
              className="rounded-md bg-white px-3.5 py-2.5 text-sm font-semibold text-primary-600 shadow-sm hover:bg-gray-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
            >
              Get started
            </Link>
          </div>
          <svg
            viewBox="0 0 1024 1024"
            className="absolute left-1/2 top-1/2 -z-10 h-[64rem] w-[64rem] -translate-x-1/2 -translate-y-1/2 [mask-image:radial-gradient(closest-side,white,transparent)]"
            aria-hidden="true"
          >
            <circle cx={512} cy={512} r={512} fill="url(#827591b1-ce8c-4110-b064-7cb85a0b1217)" fillOpacity="0.7" />
            <defs>
              <radialGradient id="827591b1-ce8c-4110-b064-7cb85a0b1217">
                <stop stopColor="#3b82f6" />
                <stop offset={1} stopColor="#1d4ed8" />
              </radialGradient>
            </defs>
          </svg>
        </div>
      </div>
    </div>
  );
}
