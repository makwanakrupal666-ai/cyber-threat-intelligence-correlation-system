import { useState } from "react";

import { mapAttackBehavior } from "../api";


function AttackPanel() {

  const [text, setText] = useState("");

  const [mappings, setMappings] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");


  async function handleAnalyze() {

    const cleanedText =
      text.trim();

    if (!cleanedText) {

      setError(
        "Enter CTI behavioral evidence first."
      );

      setMappings([]);

      return;
    }


    try {

      setLoading(true);

      setError("");

      const result =
        await mapAttackBehavior(
          cleanedText
        );


      setMappings(
        result?.mappings || []
      );

    } catch (err) {

      setError(
        err.message ||
        "MITRE ATT&CK mapping failed."
      );

      setMappings([]);

    } finally {

      setLoading(false);

    }
  }


  function getConfidencePercent(
    value
  ) {

    const number =
      Number(value || 0);

    return `${Math.round(
      number * 100
    )}%`;
  }


  return (

    <section className="attack-panel">


      {/* ================================================= */}
      {/* HEADER */}
      {/* ================================================= */}

      <div className="attack-header">

        <div>

          <span className="eyebrow">
            BEHAVIORAL ANALYSIS
          </span>

          <h3>
            MITRE ATT&CK Mapping
          </h3>

          <p>
            Map observed CTI behavior to
            candidate MITRE ATT&CK techniques.
          </p>

        </div>

      </div>


      {/* ================================================= */}
      {/* INPUT */}
      {/* ================================================= */}

      <div className="attack-input-area">

        <label>
          CTI Behavioral Evidence
        </label>


        <textarea
          value={text}
          onChange={(event) =>
            setText(
              event.target.value
            )
          }

          placeholder={
            "Example: The attacker used PowerShell " +
            "to download a payload from a remote server."
          }

          rows={5}
        />


        <div className="attack-actions">

          <button
            className="enrich-button"
            onClick={handleAnalyze}
            disabled={loading}
          >

            {loading
              ? "Analyzing..."
              : "⚡ Map to MITRE ATT&CK"}

          </button>

        </div>

      </div>


      {/* ================================================= */}
      {/* ERROR */}
      {/* ================================================= */}

      {error && (

        <div className="enrichment-error">

          <strong>
            ATT&CK Error:
          </strong>

          {" "}

          {error}

        </div>

      )}


      {/* ================================================= */}
      {/* RESULTS */}
      {/* ================================================= */}

      {mappings.length > 0 && (

        <div className="attack-results">

          <div className="attack-result-count">

            {mappings.length}

            {" "}

            technique
            {mappings.length !== 1
              ? "s"
              : ""}

            {" "}identified

          </div>


          <div className="attack-grid">

            {mappings.map(
              (mapping, index) => (

                <div
                  className="attack-card"
                  key={
                    `${mapping.technique_id}-${index}`
                  }
                >

                  <div className="attack-card-top">

                    <span className="attack-technique-id">

                      {mapping.technique_id ||
                        "Unknown"}

                    </span>


                    <span className="attack-confidence">

                      {getConfidencePercent(
                        mapping.mapping_confidence
                      )}

                    </span>

                  </div>


                  <h4>

                    {mapping.technique_name ||
                      mapping.name ||
                      "Technique"}

                  </h4>


                  {mapping.tactic && (

                    <div className="attack-field">

                      <span>
                        Tactic
                      </span>

                      <strong>
                        {mapping.tactic}
                      </strong>

                    </div>

                  )}


                  {mapping.matched_keywords && (

                    <div className="attack-field">

                      <span>
                        Matched Evidence
                      </span>

                      <strong>

                        {Array.isArray(
                          mapping.matched_keywords
                        )
                          ? mapping.matched_keywords.join(
                              ", "
                            )
                          : mapping.matched_keywords}

                      </strong>

                    </div>

                  )}


                  {mapping.method && (

                    <div className="attack-method">

                      Method:{" "}

                      {mapping.method}

                    </div>

                  )}

                </div>

              )
            )}

          </div>

        </div>

      )}


      {/* ================================================= */}
      {/* NO RESULTS */}
      {/* ================================================= */}

      {!loading &&
        !error &&
        text.trim() &&
        mappings.length === 0 && (

          <div className="attack-empty">

            No matching MITRE ATT&CK behavior
            was identified by the configured
            evidence-based rules.

          </div>

        )}

    </section>

  );
}


export default AttackPanel;