(function () {
  var code = new URLSearchParams(window.location.search).get("code") || "";
  function getCookie(name) {
    var m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
    return m ? decodeURIComponent(m[2]) : "";
  }
  fetch("/api/invite/" + code + "/check", {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-XSRF-Token": getCookie("XSRF-TOKEN") }
  }).then(function (r) { return r.json(); }).then(function (j) {
    document.getElementById("result").textContent = j.valid ? "invite ok" : "invalid invite";
  }).catch(function () {
    document.getElementById("result").textContent = "request failed";
  });
})();
