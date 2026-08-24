const getSeverity = require("./utils").getSeverity;
const getCWEId = require("./utils").getCWEId;

// `cwe` is a plain string on older audit output and an array on newer ones.
var getCWEs = function (cwe) {
  if (Array.isArray(cwe)) {
    return cwe.filter(Boolean);
  }
  return cwe ? [cwe] : [];
};

var convert = function (json) {
  parsedData = JSON.parse(json);
  report = {};
  report.version = "2.0";
  report.vulnerabilities = [];
  report.remediations = [];

  for (var id in parsedData.advisories) {
    var advisory = parsedData.advisories[id];
    var cwes = getCWEs(advisory.cwe);
    var cves = advisory.cves || [];
    var findings = advisory.findings || [];
    var paths = (findings[0] && findings[0].paths) || [];
    var cwe_id = getCWEId(cwes.length > 0 ? cwes[0] : "N/A");

    report.vulnerabilities.push({
      tool: "pnpm_audit",
      category: "dependency_scanning",
      name: advisory.module_name,
      namespace: advisory.module_name,
      message: advisory.title,
      cve: advisory.github_advisory_id
        ? `GHSA-${advisory.github_advisory_id}`
        : "N/A",
      description: advisory.overview,
      severity: getSeverity(advisory.severity),
      fixedby: advisory.recommendation,
      confidence: "High",
      scanner: {
        id: "pnpm_audit_advisories",
        name: "PNPM Audit",
      },
      location: {
        file: "pnpm-lock.yaml",
        dependency: {
          package: {
            name: advisory.module_name,
          },
          version: advisory.vulnerable_versions,
        },
      },
      identifiers: [
        ...(advisory.github_advisory_id
          ? [
              {
                type: "ghsa_id",
                name: advisory.github_advisory_id,
                value: advisory.github_advisory_id,
                url: `https://github.com/advisories/${advisory.github_advisory_id}`,
              },
            ]
          : []),
        ...(cves.length > 0
          ? [
              {
                type: "cve_id",
                name: cves[0],
                value: cves[0],
                url: `https://nvd.nist.gov/vuln/detail/${cves[0]}`,
              },
            ]
          : []),
        ...(cwes.length > 0
          ? [
              {
                type: "cwe_id",
                name: cwes[0],
                value: cwes[0],
                url: `https://cwe.mitre.org/data/definitions/${cwe_id}.html`,
              },
            ]
          : []),
      ],
      solution: advisory.recommendation,
      instances: paths.map((value) => ({ method: value })),
      // links: advisory.references
      //   .split("\n")
      //   .map((ref) => ({ url: ref.replace("- ", "").trim() }))
      //   .filter((link) => link.url !== ""),
      links: [
        {
          url: `https://npmjs.com/advisories/${advisory.id}`,
        },
      ],
    });
  }

  return JSON.stringify(report, null, "  ");
};

module.exports = convert;
