var capitalize = function (string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
};

var getCWEId = function (cweString) {
  return cweString.replace("CWE-", "");
};

var getSeverity = function (string) {
  const allowed = ["Info", "Unknown", "Low", "Medium", "High", "Critical"];
  if (allowed.includes(capitalize(string))) {
    capitalize(string);
  }
  if (capitalize(string) === "Moderate") {
    return "Medium";
  }
  return "Unknown";
};

module.exports = {
  capitalize,
  getCWEId,
  getSeverity,
};
