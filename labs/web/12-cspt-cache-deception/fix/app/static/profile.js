(function () {
  var userId = new URLSearchParams(window.location.search).get("id") || "";
  function getCookie(name) {
    var m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
    return m ? decodeURIComponent(m[2]) : "";
  }
  fetch("/v1/users/info/" + userId, {
    headers: { "X-Auth-Token": getCookie("auth_token") }
  }).then(function (r) { return r.json(); }).then(function (j) {
    document.getElementById("result").textContent = j.name || "not found";
  }).catch(function () {
    document.getElementById("result").textContent = "request failed";
  });
})();
