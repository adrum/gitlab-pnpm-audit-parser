const getSeverity = require("./utils").getSeverity;
const getCWEId = require("./utils").getCWEId;

var convert = function (json) {
  parsedData = JSON.parse(json);
  report = {};
  report.version = "2.0";
  report.vulnerabilities = [];
  report.remediations = [];

  for (var id in parsedData.advisories) {
    var advisory = parsedData.advisories[id];
    var cwe_id = getCWEId(advisory.cwe ? advisory.cwe[0] : "N/A");

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
        ...(advisory.cves.length > 0
          ? [
              {
                type: "cve_id",
                name: advisory.cves[0],
                value: advisory.cves[0],
                url: `https://nvd.nist.gov/vuln/detail/${advisory.cves[0]}`,
              },
            ]
          : []),
        ...(advisory.cwe
          ? [
              {
                type: "cwe_id",
                name: advisory.cwe[0],
                value: advisory.cwe[0],
                url: `https://cwe.mitre.org/data/definitions/${cwe_id}.html`,
              },
            ]
          : []),
      ],
      solution: advisory.recommendation,
      instances: advisory.findings[0].paths.map((value) => ({ method: value })),
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
