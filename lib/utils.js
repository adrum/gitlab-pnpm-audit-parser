module.exports.capitalize = function (string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
};

module.exports.getCWEId = function (cweString) {
  return cweString.replace("CWE-", "");
};

module.exports.getSeverity = function (string) {
  const allowed = ["Info", "Unknown", "Low", "Medium", "High", "Critical"];
  if (allowed.includes(this.capitalize(string))) {
    this.capitalize(string);
  }
  if (this.capitalize(string) === "Moderate") {
    return "Medium";
  }
  return "Unknown";
};
