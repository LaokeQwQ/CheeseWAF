import { useEffect, useRef, useState, type ReactNode } from 'react';
import { geoEquirectangular, geoGraticule10, geoPath } from 'd3-geo';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import type { AttackRegion, ThreatLevel, WorldFeature } from './AttackMapPage';
import { normalizeWorldId } from './AttackMapPage';

type GlobeMapProps = {
  regions: AttackRegion[];
  zoom: number;
  countryLevels: Map<string, ThreatLevel>;
  worldFeatures: WorldFeature[];
  fallback: ReactNode;
};

const globeLevelColors: Record<ThreatLevel, number> = {
  low: 0x2176d2,
  medium: 0xd98912,
  high: 0xf97316,
  critical: 0xdd3b3b,
};

export default function GlobeMap({ regions, zoom, countryLevels, worldFeatures, fallback }: GlobeMapProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [webglError, setWebglError] = useState(false);

  useEffect(() => {
    if (webglError) {
      return undefined;
    }
    const host = hostRef.current;
    if (!host) {
      return undefined;
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
    camera.position.set(0, 0.22, 3 / zoom);
    let renderer: any;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      setWebglError(true);
      return undefined;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    host.appendChild(renderer.domElement);

    const tooltip = document.createElement('div');
    tooltip.className = 'globe-tooltip';
    host.appendChild(tooltip);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.enablePan = false;
    controls.enableZoom = true;
    controls.minDistance = 1.55;
    controls.maxDistance = 4.4;
    controls.rotateSpeed = 0.62;
    controls.zoomSpeed = 0.78;

    const earthGroup = new THREE.Group();
    const texture = createWorldTexture(countryLevels, worldFeatures);
    const globe = new THREE.Mesh(
      new THREE.SphereGeometry(1, 128, 128),
      new THREE.MeshStandardMaterial({
        map: texture,
        roughness: 0.82,
        metalness: 0.02,
      }),
    );
    earthGroup.add(globe);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.018, 96, 96),
      new THREE.MeshBasicMaterial({
        color: 0x2f8cff,
        transparent: true,
        opacity: 0.07,
        side: THREE.BackSide,
      }),
    );
    earthGroup.add(atmosphere);

    const markerGroup = new THREE.Group();
    const markerMeshes: any[] = [];
    for (const region of regions) {
      const marker = new THREE.Mesh(
        new THREE.SphereGeometry(Math.max(0.024, Math.min(0.08, region.size / 500)), 24, 24),
        new THREE.MeshBasicMaterial({ color: globeLevelColors[region.level] }),
      );
      marker.position.copy(latLonToVector(region.lat, region.lon, 1.038));
      marker.userData.region = region;
      markerMeshes.push(marker);
      markerGroup.add(marker);
    }
    earthGroup.add(markerGroup);
    earthGroup.rotation.y = -0.35;
    scene.add(earthGroup);

    scene.add(new THREE.AmbientLight(0xffffff, 1.18));
    const light = new THREE.DirectionalLight(0xffffff, 1.8);
    light.position.set(3, 2, 4);
    scene.add(light);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const onPointerMove = (event: globalThis.PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(markerMeshes, false)[0];
      if (!hit) {
        tooltip.classList.remove('globe-tooltip-visible');
        return;
      }
      const region = hit.object.userData.region as AttackRegion;
      tooltip.textContent = `${region.locationName} · ${region.attacks}`;
      tooltip.style.left = `${event.clientX - rect.left + 12}px`;
      tooltip.style.top = `${event.clientY - rect.top + 12}px`;
      tooltip.classList.add('globe-tooltip-visible');
    };
    const onPointerLeave = () => tooltip.classList.remove('globe-tooltip-visible');
    renderer.domElement.addEventListener('pointermove', onPointerMove);
    renderer.domElement.addEventListener('pointerleave', onPointerLeave);

    const resize = () => {
      const rect = host.getBoundingClientRect();
      const width = Math.max(320, rect.width);
      const height = Math.max(320, rect.height);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.position.z = 3 / zoom;
      camera.updateProjectionMatrix();
      renderer.render(scene, camera);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();

    let frame = 0;
    const tick = () => {
      earthGroup.rotation.y += 0.0012;
      controls.update();
      renderer.render(scene, camera);
      frame = requestAnimationFrame(tick);
    };
    tick();

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      renderer.domElement.removeEventListener('pointermove', onPointerMove);
      renderer.domElement.removeEventListener('pointerleave', onPointerLeave);
      controls.dispose();
      renderer.dispose();
      texture?.dispose();
      globe.geometry.dispose();
      atmosphere.geometry.dispose();
      markerGroup.children.forEach((child: any) => {
        if (child instanceof THREE.Mesh) {
          child.geometry.dispose();
          if (Array.isArray(child.material)) {
            child.material.forEach((material: any) => material.dispose());
          } else {
            child.material.dispose();
          }
        }
      });
      host.removeChild(renderer.domElement);
      host.removeChild(tooltip);
    };
  }, [regions, zoom, countryLevels, worldFeatures, webglError]);

  if (webglError) {
    return <>{fallback}</>;
  }

  return <div ref={hostRef} className="globe-stage" />;
}

function latLonToVector(lat: number, lon: number, radius: number) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}

function createWorldTexture(countryLevels: Map<string, ThreatLevel>, worldFeatures: WorldFeature[]) {
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }
  ctx.fillStyle = '#0f766e';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  const textureProjection = geoEquirectangular()
    .scale(canvas.width / (2 * Math.PI))
    .translate([canvas.width / 2, canvas.height / 2]);
  const texturePath = geoPath(textureProjection, ctx);
  ctx.beginPath();
  texturePath(geoGraticule10() as any);
  ctx.strokeStyle = 'rgba(215,248,228,0.22)';
  ctx.lineWidth = 0.75;
  ctx.stroke();
  for (const item of worldFeatures) {
    ctx.beginPath();
    texturePath(item as any);
    ctx.fillStyle = globeFillForLevel(countryLevels.get(normalizeWorldId(item.id ?? '')));
    ctx.strokeStyle = '#0f513f';
    ctx.lineWidth = 0.72;
    ctx.fill();
    ctx.stroke();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function globeFillForLevel(level: ThreatLevel | undefined) {
  switch (level) {
    case 'critical':
      return '#ef4444';
    case 'high':
      return '#fb923c';
    case 'medium':
      return '#facc15';
    case 'low':
      return '#7dd3fc';
    default:
      return '#d7f8e4';
  }
}
