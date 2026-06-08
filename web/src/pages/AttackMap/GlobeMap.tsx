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

const markerColorFallback = 0x2176d2;

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
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.setClearColor(0x000000, 0);
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
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.45;

    const starField = createStarField();
    scene.add(starField);

    const earthGroup = new THREE.Group();
    const texture = createWorldTexture(countryLevels, worldFeatures);
    const cloudTexture = createCloudTexture();
    const globe = new THREE.Mesh(
      new THREE.SphereGeometry(1, 128, 128),
      new THREE.MeshStandardMaterial({
        map: texture,
        roughness: 0.62,
        metalness: 0.04,
        emissive: new THREE.Color(0x062634),
        emissiveIntensity: 0.12,
      }),
    );
    earthGroup.add(globe);

    const clouds = new THREE.Mesh(
      new THREE.SphereGeometry(1.012, 96, 96),
      new THREE.MeshBasicMaterial({
        map: cloudTexture,
        transparent: true,
        opacity: 0.18,
        depthWrite: false,
      }),
    );
    earthGroup.add(clouds);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.04, 96, 96),
      new THREE.MeshBasicMaterial({
        color: 0x64d7ff,
        transparent: true,
        opacity: 0.09,
        side: THREE.BackSide,
      }),
    );
    earthGroup.add(atmosphere);

    const markerGroup = new THREE.Group();
    const markerMeshes: any[] = [];
    const pulseRings: Array<{ mesh: any; material: any; phase: number }> = [];
    const flowArcs: Array<{ material: any; phase: number }> = [];
    const protectedOrigin = latLonToVector(35.9, 104.2, 1.036);
    for (const [index, region] of regions.entries()) {
      const normal = latLonToVector(region.lat, region.lon, 1).normalize();
      const color = globeLevelColors[region.level] ?? markerColorFallback;
      const markerSize = Math.max(0.024, Math.min(0.076, region.size / 520));
      const height = Math.max(0.055, Math.min(0.18, region.size / 250));

      const ringMaterial = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.46,
        depthWrite: false,
      });
      const ring = new THREE.Mesh(new THREE.TorusGeometry(markerSize * 1.45, 0.0045, 10, 42), ringMaterial);
      ring.position.copy(normal.clone().multiplyScalar(1.041));
      orientNormal(ring, normal);
      ring.userData.region = region;

      const beamMaterial = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.72,
        depthWrite: false,
      });
      const beam = new THREE.Mesh(new THREE.CylinderGeometry(markerSize * 0.11, markerSize * 0.22, height, 16, 1, true), beamMaterial);
      beam.position.copy(normal.clone().multiplyScalar(1.052 + height / 2));
      beam.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), normal);
      beam.userData.region = region;

      const tip = new THREE.Mesh(
        new THREE.SphereGeometry(markerSize, 24, 24),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.96 }),
      );
      tip.position.copy(normal.clone().multiplyScalar(1.072 + height));
      tip.userData.region = region;

      markerMeshes.push(ring, beam, tip);
      pulseRings.push({ mesh: ring, material: ringMaterial, phase: index * 0.47 });
      markerGroup.add(ring, beam, tip);
      if (index < 48) {
        const arcMaterial = new THREE.MeshBasicMaterial({
          color,
          transparent: true,
          opacity: 0.28,
          depthWrite: false,
          blending: THREE.AdditiveBlending,
        });
        const arc = createArcMesh(protectedOrigin, normal.clone().multiplyScalar(1.036), arcMaterial);
        markerGroup.add(arc);
        flowArcs.push({ material: arcMaterial, phase: index * 0.31 });
      }
    }
    earthGroup.add(markerGroup);
    earthGroup.rotation.y = -0.35;
    scene.add(earthGroup);

    scene.add(new THREE.AmbientLight(0xbdd9ff, 0.86));
    const light = new THREE.DirectionalLight(0xffffff, 1.8);
    light.position.set(3, 2, 4);
    scene.add(light);
    const rimLight = new THREE.DirectionalLight(0x7dd3fc, 0.72);
    rimLight.position.set(-3, 0.4, -2);
    scene.add(rimLight);

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

    const clock = new THREE.Clock();
    let frame = 0;
    const tick = () => {
      const delta = clock.getDelta();
      const elapsed = clock.getElapsedTime();
      controls.update(delta);
      clouds.rotation.y += delta * 0.018;
      starField.rotation.y += delta * 0.004;
      for (const item of pulseRings) {
        const wave = (Math.sin(elapsed * 2.4 + item.phase) + 1) / 2;
        item.mesh.scale.setScalar(1 + wave * 0.22);
        item.material.opacity = 0.28 + wave * 0.24;
      }
      for (const item of flowArcs) {
        const wave = (Math.sin(elapsed * 1.6 + item.phase) + 1) / 2;
        item.material.opacity = 0.18 + wave * 0.22;
      }
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
      cloudTexture?.dispose();
      starField.geometry.dispose();
      if (Array.isArray(starField.material)) {
        starField.material.forEach((material: any) => material.dispose());
      } else {
        starField.material.dispose();
      }
      earthGroup.traverse((child: any) => {
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

function orientNormal(object: any, normal: any) {
  object.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal);
}

function createArcMesh(start: any, end: any, material: any) {
  const midpoint = start.clone().add(end).normalize().multiplyScalar(1.28 + Math.min(0.26, start.distanceTo(end) * 0.09));
  const curve = new THREE.CatmullRomCurve3([start, midpoint, end]);
  return new THREE.Mesh(new THREE.TubeGeometry(curve, 46, 0.0035, 8, false), material);
}

function createStarField() {
  const count = 260;
  const positions = new Float32Array(count * 3);
  for (let index = 0; index < count; index += 1) {
    const theta = index * 2.399963229728653;
    const z = 1 - (2 * index + 1) / count;
    const radius = Math.sqrt(Math.max(0, 1 - z * z));
    const distance = 7.5 + ((index * 37) % 60) / 22;
    positions[index * 3] = Math.cos(theta) * radius * distance;
    positions[index * 3 + 1] = z * distance;
    positions[index * 3 + 2] = Math.sin(theta) * radius * distance;
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  return new THREE.Points(
    geometry,
    new THREE.PointsMaterial({
      color: 0xb8d9ff,
      size: 0.012,
      sizeAttenuation: true,
      transparent: true,
      opacity: 0.58,
      depthWrite: false,
    }),
  );
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
  const ocean = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
  ocean.addColorStop(0, '#051525');
  ocean.addColorStop(0.42, '#063b4d');
  ocean.addColorStop(1, '#0b5f6f');
  ctx.fillStyle = ocean;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = 'rgba(255,255,255,0.035)';
  for (let index = 0; index < 28; index += 1) {
    const x = (index * 131) % canvas.width;
    const y = (index * 73) % canvas.height;
    ctx.beginPath();
    ctx.ellipse(x, y, 160 + (index % 4) * 32, 28 + (index % 3) * 12, (index % 7) * 0.35, 0, Math.PI * 2);
    ctx.fill();
  }
  const textureProjection = geoEquirectangular()
    .scale(canvas.width / (2 * Math.PI))
    .translate([canvas.width / 2, canvas.height / 2]);
  const texturePath = geoPath(textureProjection, ctx);
  ctx.beginPath();
  texturePath(geoGraticule10() as any);
  ctx.strokeStyle = 'rgba(197,232,238,0.18)';
  ctx.lineWidth = 0.7;
  ctx.stroke();
  for (const item of worldFeatures) {
    ctx.beginPath();
    texturePath(item as any);
    ctx.fillStyle = globeFillForLevel(countryLevels.get(normalizeWorldId(item.id ?? '')));
    ctx.strokeStyle = 'rgba(229,246,239,0.68)';
    ctx.lineWidth = 0.62;
    ctx.fill();
    ctx.stroke();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function createCloudTexture() {
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  for (let index = 0; index < 64; index += 1) {
    const x = (index * 97) % canvas.width;
    const y = 42 + ((index * 53) % (canvas.height - 84));
    const width = 60 + (index % 7) * 18;
    const height = 12 + (index % 5) * 5;
    ctx.fillStyle = `rgba(255,255,255,${0.03 + (index % 4) * 0.012})`;
    ctx.beginPath();
    ctx.ellipse(x, y, width, height, (index % 9) * 0.18, 0, Math.PI * 2);
    ctx.fill();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function globeFillForLevel(level: ThreatLevel | undefined) {
  switch (level) {
    case 'critical':
      return '#f05252';
    case 'high':
      return '#fb923c';
    case 'medium':
      return '#f6c85f';
    case 'low':
      return '#60a5fa';
    default:
      return '#b9d9c8';
  }
}
