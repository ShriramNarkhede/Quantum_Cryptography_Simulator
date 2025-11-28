import React, { useState } from 'react';
import { ChevronDown } from 'lucide-react';

interface CollapsibleSectionProps {
  title: string;
  subtitle?: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

const CollapsibleSection: React.FC<CollapsibleSectionProps> = ({
  title,
  subtitle,
  defaultOpen = false,
  children
}) => {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className="collapsible-card">
      <button
        className="collapsible-header"
        onClick={() => setOpen(prev => !prev)}
        aria-expanded={open}
      >
        <div>
          <p className="collapsible-title">{title}</p>
          {subtitle && <p className="collapsible-subtitle">{subtitle}</p>}
        </div>
        <ChevronDown
          className={`transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          aria-hidden="true"
        />
      </button>
      {open && (
        <div className="collapsible-body">
          {children}
        </div>
      )}
    </section>
  );
};

export default CollapsibleSection;

