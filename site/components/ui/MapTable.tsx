interface MapRow {
  req: string;
  ctrl: string;
  ev: string;
}

export default function MapTable({
  headers,
  rows,
}: {
  headers: [string, string, string];
  rows: MapRow[];
}) {
  return (
    <div className="map-table" role="table">
      <div className="map-row head" role="row">
        {headers.map((header) => (
          <span key={header} role="columnheader">
            {header}
          </span>
        ))}
      </div>
      {rows.map((row) => (
        <div className="map-row" role="row" key={row.req}>
          <span className="req" role="cell">
            {row.req}
          </span>
          <span className="ctrl" role="cell">
            {row.ctrl}
          </span>
          <span className="ev" role="cell">
            {row.ev}
          </span>
        </div>
      ))}
    </div>
  );
}
