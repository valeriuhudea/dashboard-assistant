var timeleft = 3
var downloadTimer = setInterval(function() {
  if(timeleft <= 0) {
    clearInterval(downloadTimer)
    document.getElementById("countdown").innerHTML = "Redirecting"
  } else {
    document.getElementById("countdown").innerHTML = "Redirecting in " + timeleft + " seconds";
  }
  timeleft -= 1
}, 900)

setTimeout(function() {
    window.location.href = '/dashboard'
}, 4000)

