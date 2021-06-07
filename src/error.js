export function handleError(e) {
  if (typeof Honeybadger !== "undefined") {
    Honeybadger.notify(e)
  } else {
    throw e
  }
}