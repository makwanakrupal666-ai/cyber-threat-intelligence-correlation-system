function StatCard({
  title,
  value,
  subtitle,
  icon,
  className = "",
}) {
  return (
    <div
      className={`stat-card ${className}`}
    >

      <div className="stat-card-header">

        <div className="stat-card-icon">
          {icon}
        </div>

        <span>
          {title}
        </span>

      </div>


      <div className="stat-card-value">
        {value}
      </div>


      <div className="stat-card-subtitle">
        {subtitle}
      </div>

    </div>
  );
}

export default StatCard;