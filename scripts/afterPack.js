const fs = require('fs/promises');
const path = require('path');

async function removeIfExists(targetPath) {
  await fs.rm(targetPath, { recursive: true, force: true });
}

async function removeNestedDirectories(rootPath, namesToRemove) {
  let entries;
  try {
    entries = await fs.readdir(rootPath, { withFileTypes: true });
  } catch (error) {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const entryPath = path.join(rootPath, entry.name);
    if (namesToRemove.has(entry.name.toLowerCase())) {
      await removeIfExists(entryPath);
      continue;
    }

    await removeNestedDirectories(entryPath, namesToRemove);
  }
}

module.exports = async function afterPack(context) {
  const backendRoot = path.join(context.appOutDir, 'resources', 'backend');
  const runtimeRoot = path.join(context.appOutDir, 'resources', 'backend-runtime');
  const scriptRoot = path.join(backendRoot, 'venv', 'Scripts');
  const sitePackagesRoot = path.join(backendRoot, 'venv', 'Lib', 'site-packages');
  const runtimeSitePackagesRoot = path.join(runtimeRoot, 'Lib', 'site-packages');

  const removableBackendPaths = [
    path.join(backendRoot, 'tests'),
    path.join(backendRoot, '.tmp_test_runs'),
    path.join(backendRoot, '.pytest_cache'),
    path.join(backendRoot, 'logs'),
    path.join(backendRoot, 'delete-backend'),
    path.join(backendRoot, 'new-backend'),
    path.join(backendRoot, 'docs'),
  ];

  const removableScriptPaths = [
    'activate',
    'activate.bat',
    'activate.fish',
    'Activate.ps1',
    'deactivate.bat',
    'fastapi.exe',
    'hypothesis.exe',
    'normalizer.exe',
    'pip.exe',
    'pip3.exe',
    'pip3.13.exe',
    'py.test.exe',
    'pygmentize.exe',
    'pylupdate6.exe',
    'pytest.exe',
    'pyuic6.exe',
    'uvicorn.exe',
  ].map((name) => path.join(scriptRoot, name));

  const removableSitePackagePaths = [
    '_pytest',
    'pytest',
    'pytest-9.0.2.dist-info',
    'hypothesis',
    'hypothesis-6.151.9.dist-info',
    'PyQt6',
    'PyQt6-6.10.2.dist-info',
    'PyQt6_Qt6-6.10.2.dist-info',
    'PyQt6_sip-13.11.1.dist-info',
    'pip',
    'pip-26.0.1.dist-info',
    'setuptools',
    'setuptools-*.dist-info',
    'wheel',
    'wheel-*.dist-info',
  ];

  for (const targetPath of removableBackendPaths) {
    await removeIfExists(targetPath);
  }

  for (const targetPath of removableScriptPaths) {
    await removeIfExists(targetPath);
  }

  for (const name of removableSitePackagePaths) {
    if (name.includes('*')) continue;
    await removeIfExists(path.join(sitePackagesRoot, name));
  }

  try {
    const sitePackageEntries = await fs.readdir(sitePackagesRoot, { withFileTypes: true });
    for (const entry of sitePackageEntries) {
      const lowerName = entry.name.toLowerCase();
      if (
        lowerName.startsWith('setuptools-') && lowerName.endsWith('.dist-info') ||
        lowerName.startsWith('wheel-') && lowerName.endsWith('.dist-info')
      ) {
        await removeIfExists(path.join(sitePackagesRoot, entry.name));
      }
    }
  } catch (error) {
    if (error && error.code !== 'ENOENT') {
      console.warn('[afterPack] Failed to scan site-packages for cleanup:', error);
    }
  }

  await removeNestedDirectories(sitePackagesRoot, new Set(['tests', 'testing']));
  await removeNestedDirectories(runtimeSitePackagesRoot, new Set(['tests', 'testing']));
};
