import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { geoEquirectangular, geoGraticule10, geoPath } from 'd3-geo';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { useTranslation } from 'react-i18next';
import type { AttackRegion, ProtectedTarget, ThreatLevel, WorldFeature } from './AttackMapPage';
import { normalizeWorldId } from './AttackMapPage';
import { displayCountry } from '../../utils/display';
import { useAppStore } from '../../stores';
import type { ThemeName } from '../../themes/tokens';

type GlobeMapProps = {
  regions: AttackRegion[];
  zoom: number;
  countryLevels: Map<string, ThreatLevel>;
  worldFeatures: WorldFeature[];
  target?: ProtectedTarget;
  fallback: ReactNode;
  visualTheme?: GlobeVisualTheme;
};

type GlobeVisualTheme = 'light' | 'dark';

const globeLevelColors: Record<ThreatLevel, number> = {
  low: 0x2176d2,
  medium: 0xd98912,
  high: 0xf97316,
  critical: 0xdd3b3b,
};

const markerColorFallback = 0x2176d2;

export default function GlobeMap({ regions, zoom, countryLevels, worldFeatures, target, fallback, visualTheme: forcedVisualTheme }: GlobeMapProps) {
  const { t } = useTranslation();
  const appTheme = useAppStore((state) => state.theme);
  const visualTheme = forcedVisualTheme ?? resolveGlobeTheme(appTheme);
  const hostRef = useRef<HTMLDivElement>(null);
  const zoomRef = useRef(zoom);
  const tRef = useRef(t);
  const resizeRef = useRef<(() => void) | null>(null);
  const [webglError, setWebglError] = useState(false);
  const regionsSignature = useMemo(
    () => regions.map((region) => [
      region.key,
      region.lat.toFixed(4),
      region.lon.toFixed(4),
      region.attacks,
      region.level,
      Math.round(region.size),
    ].join(':')).join('|'),
    [regions],
  );
  const countryLevelsSignature = useMemo(
    () => Array.from(countryLevels.entries()).sort(([a], [b]) => a.localeCompare(b)).map(([key, level]) => `${key}:${level}`).join('|'),
    [countryLevels],
  );
  const worldSignature = useMemo(() => `${worldFeatures.length}:${worldFeatures[0]?.id ?? ''}:${worldFeatures[worldFeatures.length - 1]?.id ?? ''}`, [worldFeatures]);
  const targetSignature = target ? `${target.lat.toFixed(4)}:${target.lon.toFixed(4)}:${target.label}:${target.source}` : 'fallback';

  useEffect(() => {
    zoomRef.current = zoom;
    resizeRef.current?.();
  }, [zoom]);

  useEffect(() => {
    tRef.current = t;
  }, [t]);

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
    camera.position.set(0, 0.22, 3 / zoomRef.current);
    const isDarkGlobe = visualTheme === 'dark';
    let renderer: any;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: true,
        preserveDrawingBuffer: false,
        powerPreference: 'high-performance',
      });
    } catch {
      setWebglError(true);
      return undefined;
    }
    const isTouch = window.matchMedia('(pointer: coarse)').matches;
    const prefersReducedData = window.matchMedia?.('(prefers-reduced-data: reduce)').matches ?? false;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, prefersReducedData ? 1.12 : (isTouch ? 1.28 : 1.55)));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.06;
    renderer.setClearColor(isDarkGlobe ? 0x000000 : 0xf8fbff, 0);
    renderer.domElement.style.pointerEvents = 'auto';
    renderer.domElement.style.touchAction = 'none';
    host.appendChild(renderer.domElement);

    const tooltip = document.createElement('div');
    tooltip.className = 'globe-tooltip';
    host.appendChild(tooltip);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.enabled = true;
    controls.enableRotate = true;
    controls.enablePan = false;
    controls.enableZoom = true;
    controls.minDistance = 1.55;
    controls.maxDistance = 4.4;
    controls.rotateSpeed = 0.74;
    controls.zoomSpeed = 0.86;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.82;
    let controlsActive = false;
    const onControlsStart = () => {
      controlsActive = true;
      tooltip.classList.remove('globe-tooltip-visible');
    };
    const onControlsEnd = () => {
      window.setTimeout(() => {
        controlsActive = false;
      }, 80);
    };
    controls.addEventListener('start', onControlsStart);
    controls.addEventListener('end', onControlsEnd);

    const starField = createStarField(visualTheme);
    scene.add(starField);

    const earthGroup = new THREE.Group();
    const globeGeometry = new THREE.SphereGeometry(1, 112, 112);
    const cloudGeometry = new THREE.SphereGeometry(1.018, 96, 96);
    const atmosphereGeometry = new THREE.SphereGeometry(1.085, 96, 96);
    const markerTipGeometry = new THREE.SphereGeometry(1, 24, 24);
    const flowHeadGeometry = new THREE.SphereGeometry(0.014, 14, 14);
    const targetGeometry = new THREE.SphereGeometry(0.024, 24, 24);
    const texture = createWorldTexture(countryLevels, worldFeatures, visualTheme);
    if (texture) {
      texture.anisotropy = Math.min(8, renderer.capabilities.getMaxAnisotropy?.() ?? 1);
      texture.minFilter = THREE.LinearMipmapLinearFilter;
      texture.magFilter = THREE.LinearFilter;
    }
    const cloudTexture = createCloudTexture();
    if (cloudTexture) {
      cloudTexture.wrapS = THREE.RepeatWrapping;
      cloudTexture.anisotropy = Math.min(4, renderer.capabilities.getMaxAnisotropy?.() ?? 1);
    }
    const gridSphere = createGridSphere(1.006, visualTheme);
    const globe = new THREE.Mesh(
      globeGeometry,
      new THREE.MeshPhysicalMaterial({
        map: texture,
        roughness: isDarkGlobe ? 0.76 : 0.82,
        metalness: 0.02,
        clearcoat: isDarkGlobe ? 0.18 : 0.1,
        clearcoatRoughness: isDarkGlobe ? 0.58 : 0.7,
        emissive: new THREE.Color(isDarkGlobe ? 0x021b29 : 0xdff6fb),
        emissiveIntensity: isDarkGlobe ? 0.2 : 0.06,
      }),
    );
    earthGroup.add(globe);
    earthGroup.add(gridSphere);

    const clouds = new THREE.Mesh(
      cloudGeometry,
      new THREE.MeshBasicMaterial({
        map: cloudTexture,
        transparent: true,
        opacity: isDarkGlobe ? 0.2 : 0.16,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    );
    earthGroup.add(clouds);

    const atmosphere = new THREE.Mesh(
      atmosphereGeometry,
      new THREE.ShaderMaterial({
        uniforms: {
          glowColor: { value: new THREE.Color(isDarkGlobe ? 0x5bdcff : 0x4e9ed1) },
        },
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `,
        fragmentShader: `
          uniform vec3 glowColor;
          varying vec3 vNormal;
          void main() {
            float rim = pow(0.72 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.4);
            gl_FragColor = vec4(glowColor, clamp(rim, 0.0, 0.58));
          }
        `,
        transparent: true,
        side: THREE.BackSide,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    );
    earthGroup.add(atmosphere);

    const markerGroup = new THREE.Group();
    const markerMeshes: any[] = [];
    const pulseRings: Array<{ mesh: any; material: any; phase: number }> = [];
    const flowArcs: Array<{ material: any; head: any; headMaterial: any; curve: any; phase: number }> = [];
    const protectedTarget = target ?? { lat: 35.9, lon: 104.2, label: tRef.current('attackMap.protectedTarget'), source: 'fallback' as const };
    const protectedOrigin = latLonToVector(protectedTarget.lat, protectedTarget.lon, 1.052);
    const targetMarker = new THREE.Mesh(
      targetGeometry,
      new THREE.MeshBasicMaterial({
        color: isDarkGlobe ? 0xffffff : 0x0e7490,
        transparent: true,
        opacity: 0.96,
        depthWrite: false,
        blending: isDarkGlobe ? THREE.AdditiveBlending : THREE.NormalBlending,
      }),
    );
    targetMarker.position.copy(protectedOrigin);
    targetMarker.userData.region = { locationName: protectedTarget.label, attacks: tRef.current('attackMap.protectedTarget'), isTarget: true };
    markerMeshes.push(targetMarker);
    markerGroup.add(targetMarker);
    for (const [index, region] of regions.entries()) {
      const normal = latLonToVector(region.lat, region.lon, 1).normalize();
      const color = globeLevelColors[region.level] ?? markerColorFallback;
      const markerSize = Math.max(0.024, Math.min(0.076, region.size / 520));
      const height = Math.max(0.055, Math.min(0.18, region.size / 250));

      const ringMaterial = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.52,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      });
      const ring = new THREE.Mesh(new THREE.TorusGeometry(markerSize * 1.45, 0.0045, 10, 42), ringMaterial);
      ring.position.copy(normal.clone().multiplyScalar(1.041));
      orientNormal(ring, normal);
      ring.userData.region = region;

      const beamMaterial = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.7,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      });
      const beam = new THREE.Mesh(new THREE.CylinderGeometry(markerSize * 0.11, markerSize * 0.22, height, 16, 1, true), beamMaterial);
      beam.position.copy(normal.clone().multiplyScalar(1.052 + height / 2));
      beam.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), normal);
      beam.userData.region = region;

      const tip = new THREE.Mesh(
        markerTipGeometry,
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.98, blending: THREE.AdditiveBlending }),
      );
      tip.scale.setScalar(markerSize);
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
        const arc = createArcMesh(normal.clone().multiplyScalar(1.038), protectedOrigin, arcMaterial);
        const headMaterial = new THREE.MeshBasicMaterial({
          color,
          transparent: true,
          opacity: 0.9,
          depthWrite: false,
          blending: THREE.AdditiveBlending,
        });
        const head = new THREE.Mesh(flowHeadGeometry, headMaterial);
        head.position.copy(arc.curve.getPoint(0.12));
        markerGroup.add(arc);
        markerGroup.add(head);
        flowArcs.push({ material: arcMaterial, head, headMaterial, curve: arc.curve, phase: index * 0.31 });
      }
    }
    earthGroup.add(markerGroup);
    earthGroup.rotation.y = -0.35;
    earthGroup.rotation.x = -0.08;
    scene.add(earthGroup);

    scene.add(new THREE.AmbientLight(isDarkGlobe ? 0x8fb7d9 : 0xffffff, isDarkGlobe ? 0.32 : 0.62));
    const hemi = new THREE.HemisphereLight(isDarkGlobe ? 0xa9e5ff : 0xf4fbff, isDarkGlobe ? 0x06101c : 0xb9d9e6, isDarkGlobe ? 0.82 : 0.9);
    scene.add(hemi);
    const light = new THREE.DirectionalLight(0xffffff, isDarkGlobe ? 2.35 : 1.78);
    light.position.set(3.4, 2.2, 4.2);
    scene.add(light);
    const rimLight = new THREE.DirectionalLight(isDarkGlobe ? 0x74e0ff : 0x3b8dbc, isDarkGlobe ? 1.15 : 0.48);
    rimLight.position.set(-3.4, 0.55, -2.3);
    scene.add(rimLight);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    let lastPointerRaycast = 0;
    const onPointerMove = (event: globalThis.PointerEvent) => {
      if (controlsActive) {
        tooltip.classList.remove('globe-tooltip-visible');
        return;
      }
      const now = performance.now();
      if (now - lastPointerRaycast < 34) {
        return;
      }
      lastPointerRaycast = now;
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(markerMeshes, false)[0];
      if (!hit) {
        tooltip.classList.remove('globe-tooltip-visible');
        return;
      }
      const region = hit.object.userData.region as AttackRegion & { isTarget?: boolean };
      tooltip.textContent = region.isTarget
        ? `${protectedTarget.label} · ${tRef.current('attackMap.protectedTarget')}`
        : `${formatGlobeRegionLocation(region, tRef.current)} · ${region.attacks}`;
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
      const narrow = width < 560;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.position.y = narrow ? 0.08 : 0.22;
      camera.position.z = (narrow ? 3.65 : 3) / zoomRef.current;
      camera.updateProjectionMatrix();
      controls.update();
      renderer.render(scene, camera);
    };
    resizeRef.current = resize;
    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();

    const startedAt = performance.now();
    let lastFrameAt = startedAt;
    let frame = 0;
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    let hidden = document.visibilityState === 'hidden';
    let reducedMotion = motionQuery.matches;
    const updatePause = () => {
      hidden = document.visibilityState === 'hidden';
      reducedMotion = motionQuery.matches;
    };
    document.addEventListener('visibilitychange', updatePause);
    motionQuery.addEventListener('change', updatePause);

    const tick = () => {
      const now = performance.now();
      if (hidden) {
        lastFrameAt = now;
        frame = requestAnimationFrame(tick);
        return;
      }
      const delta = Math.min((now - lastFrameAt) / 1000, 0.05);
      const elapsed = (now - startedAt) / 1000;
      lastFrameAt = now;
      controls.autoRotate = true;
      controls.autoRotateSpeed = reducedMotion ? 0.24 : 0.82;
      controls.update(delta);
      earthGroup.rotation.y += delta * (reducedMotion ? 0.004 : 0.012);
      clouds.rotation.y += delta * (reducedMotion ? 0.008 : 0.024);
      clouds.rotation.x = Math.sin(elapsed * 0.12) * (reducedMotion ? 0.004 : 0.012);
      starField.rotation.y += delta * (reducedMotion ? 0.0015 : 0.004);
      for (const item of pulseRings) {
        const wave = (Math.sin(elapsed * (reducedMotion ? 1.2 : 2.4) + item.phase) + 1) / 2;
        item.mesh.scale.setScalar(1 + wave * (reducedMotion ? 0.08 : 0.22));
        item.material.opacity = 0.28 + wave * (reducedMotion ? 0.12 : 0.24);
      }
      for (const item of flowArcs) {
        const wave = (Math.sin(elapsed * (reducedMotion ? 0.8 : 1.6) + item.phase) + 1) / 2;
        const progress = (elapsed * (reducedMotion ? 0.06 : 0.16) + item.phase) % 1;
        item.material.opacity = 0.14 + wave * (reducedMotion ? 0.12 : 0.24);
        item.head.position.copy(item.curve.getPoint(progress));
        item.headMaterial.opacity = 0.32 + Math.sin(progress * Math.PI) * (reducedMotion ? 0.3 : 0.58);
      }
      renderer.render(scene, camera);
      frame = requestAnimationFrame(tick);
    };
    tick();

    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener('visibilitychange', updatePause);
      motionQuery.removeEventListener('change', updatePause);
      observer.disconnect();
      renderer.domElement.removeEventListener('pointermove', onPointerMove);
      renderer.domElement.removeEventListener('pointerleave', onPointerLeave);
      controls.removeEventListener('start', onControlsStart);
      controls.removeEventListener('end', onControlsEnd);
      controls.dispose();
      renderer.dispose();
      disposeObjectTree(starField, earthGroup);
      texture?.dispose();
      cloudTexture?.dispose();
      if (resizeRef.current === resize) {
        resizeRef.current = null;
      }
      if (renderer.domElement.parentNode === host) {
        host.removeChild(renderer.domElement);
      }
      if (tooltip.parentNode === host) {
        host.removeChild(tooltip);
      }
    };
  }, [regionsSignature, countryLevelsSignature, worldSignature, targetSignature, webglError, visualTheme]);

  if (webglError) {
    return <>{fallback}</>;
  }

  return <div ref={hostRef} className={`globe-stage globe-stage-${visualTheme}`} />;
}

function resolveGlobeTheme(theme: ThemeName): GlobeVisualTheme {
  return theme === 'dark' || theme === 'blackGold' ? 'dark' : 'light';
}

function orientNormal(object: any, normal: any) {
  object.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal);
}

function formatGlobeRegionLocation(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  const country = displayCountry(region.countryCode, t);
  if (region.locationName && region.locationName !== region.countryCode && region.locationName !== 'UNLOCATED') {
    return `${country} · ${region.locationName}`;
  }
  return country;
}

function createArcMesh(start: any, end: any, material: any) {
  const midpoint = start.clone().add(end).normalize().multiplyScalar(1.28 + Math.min(0.26, start.distanceTo(end) * 0.09));
  const curve = new THREE.CatmullRomCurve3([start, midpoint, end]);
  const mesh = new THREE.Mesh(new THREE.TubeGeometry(curve, 58, 0.0032, 8, false), material) as any;
  mesh.curve = curve;
  return mesh;
}

function createGridSphere(radius: number, visualTheme: GlobeVisualTheme) {
  const isDarkGlobe = visualTheme === 'dark';
  const group = new THREE.Group();
  const material = new THREE.LineBasicMaterial({
    color: isDarkGlobe ? 0x8ce8ff : 0x27799d,
    transparent: true,
    opacity: isDarkGlobe ? 0.16 : 0.11,
    depthWrite: false,
    blending: isDarkGlobe ? THREE.AdditiveBlending : THREE.NormalBlending,
  });

  for (let lon = -180; lon < 180; lon += 15) {
    group.add(createGeoLine(Array.from({ length: 73 }, (_, index) => ({
      lat: -90 + index * 2.5,
      lon,
    })), radius, material));
  }

  for (let lat = -75; lat <= 75; lat += 15) {
    group.add(createGeoLine(Array.from({ length: 145 }, (_, index) => ({
      lat,
      lon: -180 + index * 2.5,
    })), radius, material));
  }

  return group;
}

function createGeoLine(points: Array<{ lat: number; lon: number }>, radius: number, material: any) {
  const geometry = new THREE.BufferGeometry().setFromPoints(points.map((point) => latLonToVector(point.lat, point.lon, radius)));
  return new THREE.Line(geometry, material);
}

function disposeObjectTree(...objects: any[]) {
  const geometries = new Set<any>();
  const materials = new Set<any>();
  objects.forEach((object) => {
    object.traverse((child: any) => {
      if (child.geometry instanceof THREE.BufferGeometry) {
        geometries.add(child.geometry);
      }
      const material = child.material;
      if (Array.isArray(material)) {
        material.forEach((item) => item instanceof THREE.Material && materials.add(item));
      } else if (material instanceof THREE.Material) {
        materials.add(material);
      }
    });
  });
  geometries.forEach((geometry) => geometry.dispose());
  materials.forEach((material) => material.dispose());
}

function createStarField(visualTheme: GlobeVisualTheme) {
  const isDarkGlobe = visualTheme === 'dark';
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
      color: isDarkGlobe ? 0xb8d9ff : 0x2e7da4,
      size: isDarkGlobe ? 0.012 : 0.009,
      sizeAttenuation: true,
      transparent: true,
      opacity: isDarkGlobe ? 0.58 : 0.16,
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

function createWorldTexture(countryLevels: Map<string, ThreatLevel>, worldFeatures: WorldFeature[], visualTheme: GlobeVisualTheme) {
  const isDarkGlobe = visualTheme === 'dark';
  const canvas = document.createElement('canvas');
  canvas.width = 1536;
  canvas.height = 768;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }
  const ocean = ctx.createRadialGradient(
    canvas.width * 0.42,
    canvas.height * 0.42,
    canvas.width * 0.02,
    canvas.width * 0.52,
    canvas.height * 0.55,
    canvas.width * 0.76,
  );
  if (isDarkGlobe) {
    ocean.addColorStop(0, '#0e5667');
    ocean.addColorStop(0.42, '#083444');
    ocean.addColorStop(0.78, '#031829');
    ocean.addColorStop(1, '#020814');
  } else {
    ocean.addColorStop(0, '#f0fbff');
    ocean.addColorStop(0.38, '#d7edf8');
    ocean.addColorStop(0.74, '#abd4e4');
    ocean.addColorStop(1, '#79b7ce');
  }
  ctx.fillStyle = ocean;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  for (let index = 0; index < 90; index += 1) {
    const x = (index * 239) % canvas.width;
    const y = (index * 131) % canvas.height;
    const width = 170 + (index % 9) * 48;
    const height = 14 + (index % 5) * 10;
    ctx.fillStyle = isDarkGlobe
      ? `rgba(115, 221, 244, ${0.014 + (index % 4) * 0.006})`
      : `rgba(255, 255, 255, ${0.08 + (index % 4) * 0.014})`;
    ctx.beginPath();
    ctx.ellipse(x, y, width, height, (index % 11) * 0.21, 0, Math.PI * 2);
    ctx.fill();
  }

  const textureProjection = geoEquirectangular()
    .scale(canvas.width / (2 * Math.PI))
    .translate([canvas.width / 2, canvas.height / 2]);
  const texturePath = geoPath(textureProjection, ctx);

  ctx.beginPath();
  texturePath(geoGraticule10() as any);
  ctx.strokeStyle = isDarkGlobe ? 'rgba(130,226,239,0.08)' : 'rgba(35,97,124,0.12)';
  ctx.lineWidth = 0.9;
  ctx.stroke();

  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  for (const item of worldFeatures) {
    const level = countryLevels.get(normalizeWorldId(item.id ?? ''));
    ctx.beginPath();
    texturePath(item as any);
    ctx.shadowColor = globeShadowForLevel(level, visualTheme);
    ctx.shadowBlur = level ? (isDarkGlobe ? 18 : 10) : (isDarkGlobe ? 3 : 1);
    ctx.fillStyle = globeFillForLevel(level, visualTheme);
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  for (const item of worldFeatures) {
    const level = countryLevels.get(normalizeWorldId(item.id ?? ''));
    ctx.beginPath();
    texturePath(item as any);
    ctx.strokeStyle = level
      ? (isDarkGlobe ? 'rgba(255,241,224,0.86)' : 'rgba(255,255,255,0.86)')
      : (isDarkGlobe ? 'rgba(196,239,226,0.42)' : 'rgba(49,92,112,0.34)');
    ctx.lineWidth = level ? (isDarkGlobe ? 1.4 : 1.25) : 0.72;
    ctx.stroke();
  }

  const vignette = ctx.createRadialGradient(canvas.width * 0.5, canvas.height * 0.45, 0, canvas.width * 0.5, canvas.height * 0.5, canvas.width * 0.66);
  vignette.addColorStop(0, isDarkGlobe ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.24)');
  vignette.addColorStop(0.52, 'rgba(255,255,255,0)');
  vignette.addColorStop(1, isDarkGlobe ? 'rgba(0,4,10,0.28)' : 'rgba(22,86,113,0.14)');
  ctx.fillStyle = vignette;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.wrapS = THREE.RepeatWrapping;
  return texture;
}

function createCloudTexture() {
  const canvas = document.createElement('canvas');
  canvas.width = 768;
  canvas.height = 384;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.filter = 'blur(3px)';
  for (let index = 0; index < 96; index += 1) {
    const x = (index * 113) % canvas.width;
    const y = 34 + ((index * 67) % (canvas.height - 68));
    const baseWidth = 46 + (index % 8) * 19;
    const baseHeight = 8 + (index % 6) * 5;
    for (let lobe = 0; lobe < 3; lobe += 1) {
      ctx.fillStyle = `rgba(255,255,255,${0.026 + ((index + lobe) % 5) * 0.01})`;
      ctx.beginPath();
      ctx.ellipse(
        x + lobe * baseWidth * 0.18,
        y + ((lobe * 17 + index) % 13) - 6,
        baseWidth * (0.82 + lobe * 0.18),
        baseHeight * (0.8 + lobe * 0.16),
        (index % 9) * 0.18,
        0,
        Math.PI * 2,
      );
      ctx.fill();
    }
  }
  ctx.filter = 'none';
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function globeFillForLevel(level: ThreatLevel | undefined, visualTheme: GlobeVisualTheme) {
  if (visualTheme === 'light') {
    switch (level) {
      case 'critical':
        return '#ef5353';
      case 'high':
        return '#fb923c';
      case 'medium':
        return '#f3c75e';
      case 'low':
        return '#66a9ee';
      default:
        return '#d7eadb';
    }
  }
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
      return '#9ec8b9';
  }
}

function globeShadowForLevel(level: ThreatLevel | undefined, visualTheme: GlobeVisualTheme) {
  if (visualTheme === 'light') {
    switch (level) {
      case 'critical':
        return 'rgba(239, 83, 83, 0.46)';
      case 'high':
        return 'rgba(251, 146, 60, 0.36)';
      case 'medium':
        return 'rgba(222, 164, 40, 0.28)';
      case 'low':
        return 'rgba(72, 137, 210, 0.28)';
      default:
        return 'rgba(69, 119, 100, 0.08)';
    }
  }
  switch (level) {
    case 'critical':
      return 'rgba(248, 81, 73, 0.9)';
    case 'high':
      return 'rgba(251, 146, 60, 0.78)';
    case 'medium':
      return 'rgba(246, 200, 95, 0.65)';
    case 'low':
      return 'rgba(96, 165, 250, 0.56)';
    default:
      return 'rgba(143, 216, 202, 0.22)';
  }
}
