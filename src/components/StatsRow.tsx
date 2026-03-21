interface StatsRowProps {
  stats: {
    total: number;
    safe: number;
    unsafe: number;
    pending: number;
    errors: number;
  };
}

export default function StatsRow({ stats }: StatsRowProps) {
  const cards = [
    { label: 'Total', value: stats.total, color: 'bg-gray-700', textColor: 'text-gray-300' },
    { label: 'Safe', value: stats.safe, color: 'bg-green-900', textColor: 'text-green-400' },
    { label: 'Unsafe', value: stats.unsafe, color: 'bg-red-900', textColor: 'text-red-400' },
    { label: 'Pending', value: stats.pending, color: 'bg-yellow-900', textColor: 'text-yellow-400' },
    { label: 'Errors', value: stats.errors, color: 'bg-gray-800', textColor: 'text-gray-400' },
  ];

  return (
    <div className="grid grid-cols-5 gap-3 mb-6">
      {cards.map(card => (
        <div key={card.label} className={`${card.color} rounded-lg p-3 text-center`}>
          <div className={`text-2xl font-bold ${card.textColor}`}>{card.value}</div>
          <div className="text-xs text-gray-400 uppercase tracking-wide">{card.label}</div>
        </div>
      ))}
    </div>
  );
}
