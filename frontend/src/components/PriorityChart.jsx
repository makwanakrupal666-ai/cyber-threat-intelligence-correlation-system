import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts";


const PRIORITY_COLORS = {
  High: "#dc2626",
  Medium: "#d97706",
  Low: "#16a34a",
};


function PriorityChart({
  priorityDistribution,
}) {

  const data = [
    {
      name: "High",
      count:
        priorityDistribution.High || 0,
    },
    {
      name: "Medium",
      count:
        priorityDistribution.Medium || 0,
    },
    {
      name: "Low",
      count:
        priorityDistribution.Low || 0,
    },
  ];


  return (
    <div className="chart-card">

      <div className="section-heading">

        <div>

          <h2>
            Priority Distribution
          </h2>

          <p>
            Research-based IOC
            prioritization.
          </p>

        </div>

      </div>


      <div className="chart-container">

        <ResponsiveContainer
          width="100%"
          height="100%"
        >

          <BarChart
            data={data}
            margin={{
              top: 15,
              right: 15,
              left: -10,
              bottom: 5,
            }}
          >

            <CartesianGrid
              stroke="#edf0f5"
              strokeDasharray="3 3"
              vertical={false}
            />


            <XAxis
              dataKey="name"
              axisLine={false}
              tickLine={false}
              tick={{
                fill: "#68758a",
                fontSize: 11,
              }}
            />


            <YAxis
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
              tick={{
                fill: "#68758a",
                fontSize: 10,
              }}
            />


            <Tooltip
              cursor={{
                fill: "#f8fafc",
              }}
              contentStyle={{
                border:
                  "1px solid #e2e8f0",
                borderRadius: "8px",
                background: "#ffffff",
                color: "#172033",
                fontSize: "11px",
              }}
            />


            <Bar
              dataKey="count"
              radius={[
                6,
                6,
                0,
                0,
              ]}
              maxBarSize={58}
            >

              {data.map(
                (entry) => (

                  <Cell
                    key={entry.name}
                    fill={
                      PRIORITY_COLORS[
                        entry.name
                      ]
                    }
                  />

                )
              )}

            </Bar>

          </BarChart>

        </ResponsiveContainer>

      </div>

    </div>
  );
}


export default PriorityChart;