function getPriorityClass(priority) {
  if (priority === "High") {
    return "priority-high";
  }

  if (priority === "Medium") {
    return "priority-medium";
  }

  return "priority-low";
}


function IOCTable({
  records,
  loading,
  onSelect,
}) {
  return (
    <div className="table-card">
      <div className="section-heading">
        <div>
          <h2>Threat Intelligence Records</h2>

          <p>
            Latest stored indicators with
            transparent prioritization.
          </p>
        </div>

        <span className="record-count">
          {records.length} records
        </span>
      </div>

      {loading ? (
        <div className="loading-state">
          Loading IOC records...
        </div>
      ) : records.length === 0 ? (
        <div className="empty-state">
          No IOC records found.
        </div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>IOC</th>
                <th>Type</th>
                <th>Sources</th>
                <th>Confidence</th>
                <th>Score</th>
                <th>Priority</th>
              </tr>
            </thead>

            <tbody>
              {records.map(
                (record, index) => (
                  <tr
                    key={`${record.ioc_type}-${record.ioc_value}-${index}`}
                    onClick={() =>
                      onSelect(record)
                    }
                    className="clickable-row"
                  >
                    <td>
                      <code>
                        {record.ioc_value}
                      </code>
                    </td>

                    <td>
                      <span className="type-badge">
                        {record.ioc_type}
                      </span>
                    </td>

                    <td>
                      {record.source_count}
                    </td>

                    <td>
                      {record.confidence}%
                    </td>

                    <td>
                      {record.priority_score}
                    </td>

                    <td>
                      <span
                        className={`priority-badge ${getPriorityClass(
                          record.priority
                        )}`}
                      >
                        {record.priority}
                      </span>
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default IOCTable;