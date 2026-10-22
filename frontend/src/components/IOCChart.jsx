import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from "recharts";


const CHART_COLORS = [
  "#2563eb",
  "#7c3aed",
  "#0891b2",
  "#ea580c",
  "#16a34a",
  "#db2777",
];


function IOCChart({ statistics }) {
  const data = [
    {
      name: "IP",
      value: statistics.ip || 0,
    },
    {
      name: "Domain",
      value: statistics.domain || 0,
    },
    {
      name: "URL",
      value: statistics.url || 0,
    },
    {
      name: "MD5",
      value: statistics.md5 || 0,
    },
    {
      name: "SHA-1",
      value: statistics.sha1 || 0,
    },
    {
      name: "SHA-256",
      value: statistics.sha256 || 0,
    },
  ].filter(
    (item) => item.value > 0
  );


  return (
    <div className="chart-card">

      <div className="section-heading">

        <div>
          <h2>
            IOC Distribution
          </h2>

          <p>
            Distribution of collected
            indicators by type.
          </p>
        </div>

      </div>


      <div className="chart-container">

        {data.length === 0 ? (

          <div className="empty-state">
            No IOC data available.
          </div>

        ) : (

          <ResponsiveContainer
            width="100%"
            height="100%"
          >

            <PieChart>

              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="48%"
                innerRadius={62}
                outerRadius={100}
                paddingAngle={3}
                stroke="#ffffff"
                strokeWidth={3}
              >

                {data.map(
                  (entry, index) => (

                    <Cell
                      key={
                        `cell-${index}`
                      }
                      fill={
                        CHART_COLORS[
                          index %
                          CHART_COLORS.length
                        ]
                      }
                    />

                  )
                )}

              </Pie>


              <Tooltip
                contentStyle={{
                  border:
                    "1px solid #e2e8f0",
                  borderRadius: "8px",
                  background: "#ffffff",
                  color: "#172033",
                  fontSize: "11px",
                }}
              />


              <Legend
                verticalAlign="bottom"
                height={36}
                iconType="circle"
              />

            </PieChart>

          </ResponsiveContainer>

        )}

      </div>

    </div>
  );
}


export default IOCChart;