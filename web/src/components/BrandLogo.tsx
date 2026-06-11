type BrandLogoProps = {
  className?: string;
  alt?: string;
};

export default function BrandLogo({ className = '', alt = 'CheeseWAF logo' }: BrandLogoProps) {
  return (
    <img
      className={['brand-logo', className].filter(Boolean).join(' ')}
      src="/cheesewaf-logo.png"
      alt={alt}
      draggable={false}
    />
  );
}
