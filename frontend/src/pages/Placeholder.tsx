import { Card, EmptyState } from "@/components/ui";

export default function Placeholder({ title, message }: { title: string; message: string }) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
      </div>
      <Card>
        <EmptyState message={message} />
      </Card>
    </div>
  );
}
