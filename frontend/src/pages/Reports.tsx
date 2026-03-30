import { useEffect, useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, CheckCircle, XCircle } from 'lucide-react';
import { uploadReport, getReports } from '../api/reports';
import { getProjects } from '../api/projects';

/* ---------- Types ---------- */

interface Report {
  id: string;
  file_name: string;
  tool_name: string | null;
  project_id: string;
  project_name?: string;
  parsed: boolean;
  findings_count: number;
  uploaded_at: string;
  created_at: string;
}

interface Project {
  id: string;
  name: string;
}

const TOOL_OPTIONS = ['burpsuite', 'nessus', 'sonarqube', 'generic'] as const;

/* ---------- Page ---------- */

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  /* Upload state */
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadProject, setUploadProject] = useState('');
  const [uploadTool, setUploadTool] = useState('');
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');

  /* Dropzone */
  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setUploadFile(acceptedFiles[0]);
      setUploadError('');
      setUploadSuccess('');
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/json': ['.json'],
      'application/xml': ['.xml'],
      'text/xml': ['.xml'],
      'text/csv': ['.csv'],
    },
    maxFiles: 1,
  });

  /* Fetch data */
  useEffect(() => {
    const load = async () => {
      try {
        const [repRes, projRes] = await Promise.all([
          getReports(),
          getProjects(),
        ]);
        setReports(repRes.items ?? repRes.results ?? repRes);
        setProjects(projRes.items ?? projRes.results ?? projRes);
      } catch {
        setError('Failed to load reports.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  /* Upload handler */
  const handleUpload = async () => {
    setUploadError('');
    setUploadSuccess('');

    if (!uploadFile) {
      setUploadError('Please select a file to upload.');
      return;
    }
    if (!uploadProject) {
      setUploadError('Please select a project.');
      return;
    }

    setUploading(true);
    try {
      const result = await uploadReport(
        uploadFile,
        uploadProject,
        uploadTool || undefined
      );
      setUploadSuccess(`Report uploaded successfully. ${result.findings_count ?? 0} findings parsed.`);
      setUploadFile(null);
      setUploadTool('');
      /* Refresh list */
      const repRes = await getReports();
      setReports(repRes.items ?? repRes.results ?? repRes);
    } catch {
      setUploadError('Failed to upload report. Please check the file format.');
    } finally {
      setUploading(false);
    }
  };

  /* Helper: resolve project name */
  const projectName = (pid: string) =>
    projects.find((p) => p.id === pid)?.name ?? pid.slice(0, 8) + '...';

  return (
    <div className="space-y-6">
      {/* ---- Header ---- */}
      <h1 className="text-2xl font-bold text-gray-900">Report Management</h1>

      {error && (
        <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {/* ---- Upload section ---- */}
      <div className="rounded-lg bg-white p-6 shadow">
        <h2 className="mb-4 text-lg font-semibold text-gray-800">Upload Report</h2>

        {uploadError && (
          <div className="mb-3 rounded-lg bg-red-50 p-3 text-sm text-red-700">{uploadError}</div>
        )}
        {uploadSuccess && (
          <div className="mb-3 rounded-lg bg-green-50 p-3 text-sm text-green-700">{uploadSuccess}</div>
        )}

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* Dropzone */}
          <div className="lg:col-span-2">
            <div
              {...getRootProps()}
              className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed
                         px-6 py-10 transition-colors
                         ${isDragActive
                           ? 'border-primary-400 bg-primary-50'
                           : 'border-gray-300 bg-gray-50 hover:border-gray-400'}`}
            >
              <input {...getInputProps()} />
              <Upload className={`h-10 w-10 ${isDragActive ? 'text-primary-500' : 'text-gray-400'}`} />
              {uploadFile ? (
                <div className="mt-3 text-center">
                  <p className="text-sm font-medium text-gray-700">{uploadFile.name}</p>
                  <p className="text-xs text-gray-500">
                    {(uploadFile.size / 1024).toFixed(1)} KB
                  </p>
                </div>
              ) : (
                <div className="mt-3 text-center">
                  <p className="text-sm font-medium text-gray-700">
                    Drop report file here or click to browse
                  </p>
                  <p className="mt-1 text-xs text-gray-500">
                    Supported: .json, .xml, .csv
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Options */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Project <span className="text-red-500">*</span>
              </label>
              <select
                value={uploadProject}
                onChange={(e) => setUploadProject(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                           focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
              >
                <option value="">Select project...</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Tool (optional)
              </label>
              <select
                value={uploadTool}
                onChange={(e) => setUploadTool(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                           focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
              >
                <option value="">Auto-detect</option>
                {TOOL_OPTIONS.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleUpload}
              disabled={uploading || !uploadFile}
              className="w-full rounded-lg bg-primary-600 px-4 py-2.5 text-sm font-semibold text-white
                         transition-colors hover:bg-primary-700 disabled:opacity-60"
            >
              {uploading ? 'Uploading...' : 'Upload Report'}
            </button>
          </div>
        </div>
      </div>

      {/* ---- Reports table ---- */}
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white shadow-sm">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {['File', 'Tool', 'Project', 'Parsed', 'Findings', 'Uploaded'].map((h) => (
                <th
                  key={h}
                  className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 6 }).map((__, j) => (
                      <td key={j} className="px-6 py-4">
                        <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200" />
                      </td>
                    ))}
                  </tr>
                ))
              : reports.length === 0
                ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-sm text-gray-500">
                      No reports uploaded yet.
                    </td>
                  </tr>
                )
                : reports.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-gray-400" />
                        <span className="text-sm font-medium text-gray-700">{r.file_name}</span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      {r.tool_name || '--'}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-700">
                      {r.project_name || projectName(r.project_id)}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      {r.parsed ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-400" />
                      )}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-700">
                      {r.findings_count ?? 0}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      {new Date(r.uploaded_at || r.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
