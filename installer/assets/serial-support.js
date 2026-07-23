// Neutral Web Serial feature detection: reveal the manual-download note when
// the API is absent in this environment. No support claim is made, no data is
// collected, and no network request is issued.
if (!("serial" in navigator)) {
  const note = document.getElementById("serial-note");
  if (note) note.hidden = false;
}
