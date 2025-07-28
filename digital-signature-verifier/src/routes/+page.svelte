<script>
  import { invoke } from "@tauri-apps/api/core";
  let results = '';

  async function verifyCertificates() {
    results = await invoke('verify_certificates');
  const resultsDiv = document.querySelector('.results');

  if (resultsDiv) {
    resultsDiv.classList.add('show');
  }
  }
  
</script>

<main>
  <h1>Certificate Verification</h1>
  <button on:click={verifyCertificates}>Verify Certificates</button>
  <div>
    <h2>Results</h2>
    <pre>{results}</pre>
  </div>
</main>

<style>
  :root {
    --primary-color: #4caf50;
    --secondary-color: #ffffff;
    --background-color: #f9f9f9;
    --text-color: #333333;
    --button-hover-color: #45a049;
    --border-radius: 8px;
  }

  main {
    text-align: center;
    padding: 2em;
    background-color: var(--background-color);
    color: var(--text-color);
  }

  h1 {
    color: var(--primary-color);
    font-size: 2.5em;
    margin-bottom: 0.5em;
  }

  button {
    background-color: var(--primary-color);
    color: var(--secondary-color);
    border: none;
    padding: 0.75em 1.5em;
    font-size: 1.1em;
    cursor: pointer;
    border-radius: var(--border-radius);
    transition: background-color 0.3s ease;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }

  button:hover {
    background-color: var(--button-hover-color);
  }

  div {
    margin-top: 2em;
    padding: 1em;
    background-color: var(--secondary-color);
    border-radius: var(--border-radius);
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }

  h2 {
    color: var(--primary-color);
    font-size: 2em;
    margin-bottom: 0.5em;
  }

  pre {
    text-align: left;
    background: #f4f4f4;
    padding: 1em;
    border: 1px solid #ddd;
    border-radius: var(--border-radius);
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
  }
  
</style>
