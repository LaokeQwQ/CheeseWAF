import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { geoEquirectangular, geoGraticule10, geoPath } from 'd3-geo';
import {
  ACESFilmicToneMapping,
  AdditiveBlending,
  BackSide,
  LinearFilter,
  LinearMipmapLinearFilter,
  NormalBlending,
  RepeatWrapping,
  SRGBColorSpace,
} from 'three/src/constants.js';
import { AmbientLight } from 'three/src/lights/AmbientLight.js';
import { BufferAttribute } from 'three/src/core/BufferAttribute.js';
import { BufferGeometry } from 'three/src/core/BufferGeometry.js';
import { CanvasTexture } from 'three/src/textures/CanvasTexture.js';
import { CatmullRomCurve3 } from 'three/src/extras/curves/CatmullRomCurve3.js';
import { Color } from 'three/src/math/Color.js';
import { CylinderGeometry } from 'three/src/geometries/CylinderGeometry.js';
import { DirectionalLight } from 'three/src/lights/DirectionalLight.js';
import { Group } from 'three/src/objects/Group.js';
import { HemisphereLight } from 'three/src/lights/HemisphereLight.js';
import { Line } from 'three/src/objects/Line.js';
import { LineBasicMaterial } from 'three/src/materials/LineBasicMaterial.js';
import { Material } from 'three/src/materials/Material.js';
import { Mesh } from 'three/src/objects/Mesh.js';
import { MeshBasicMaterial } from 'three/src/materials/MeshBasicMaterial.js';
import { MeshPhysicalMaterial } from 'three/src/materials/MeshPhysicalMaterial.js';
import { PerspectiveCamera } from 'three/src/cameras/PerspectiveCamera.js';
import { Points } from 'three/src/objects/Points.js';
import { PointsMaterial } from 'three/src/materials/PointsMaterial.js';
import { Raycaster } from 'three/src/core/Raycaster.js';
import { Scene } from 'three/src/scenes/Scene.js';
import { ShaderMaterial } from 'three/src/materials/ShaderMaterial.js';
import { SphereGeometry } from 'three/src/geometries/SphereGeometry.js';
import { TorusGeometry } from 'three/src/geometries/TorusGeometry.js';
import { TubeGeometry } from 'three/src/geometries/TubeGeometry.js';
import { Vector2 } from 'three/src/math/Vector2.js';
import { Vector3 } from 'three/src/math/Vector3.js';
import { WebGLRenderer } from 'three/src/renderers/WebGLRenderer.js';
import { useTranslation } from 'react-i18next';
import { normalizeWorldId, type AttackRegion, type ProtectedTarget, type ThreatLevel, type WorldFeature } from './attackMapData';
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

type GlobeRuntime = {
  renderer: any;
  scene: any;
  camera: any;
  tooltip: HTMLDivElement;
  markerGroup: any;
  markerMeshes: any[];
  regionObjects: Map<string, any[]>;
  pulseRings: Array<{ mesh: any; material: any; phase: number }>;
  flowArcs: Array<{ material: any; head: any; headMaterial: any; curve: any; phase: number }>;
  globeMaterial: any;
  worldTexture: any;
  protectedTarget: ProtectedTarget;
  render: () => void;
};

export default function GlobeMap({ regions, zoom, countryLevels, worldFeatures, target, fallback, visualTheme: forcedVisualTheme }: GlobeMapProps) {
  const { t } = useTranslation();
  const appTheme = useAppStore((state) => state.theme);
  const visualTheme = forcedVisualTheme ?? resolveGlobeTheme(appTheme);
  const hostRef = useRef<HTMLDivElement>(null);
  const zoomRef = useRef(zoom);
  const tRef = useRef(t);
  const resizeRef = useRef<(() => void) | null>(null);
  const runtimeRef = useRef<GlobeRuntime | null>(null);
  const regionsRef = useRef(regions);
  const countryLevelsRef = useRef(countryLevels);
  const worldFeaturesRef = useRef(worldFeatures);
  const targetRef = useRef(target);
  const [webglError, setWebglError] = useState(false);
  regionsRef.current = regions;
  countryLevelsRef.current = countryLevels;
  worldFeaturesRef.current = worldFeatures;
  targetRef.current = target;
  const regionsSignature = useMemo(
    () => regions.map((region) => [
      region.key,
      region.lat.toFixed(4),
      region.lon.toFixed(4),
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

    const scene = new Scene();
    const camera = new PerspectiveCamera(42, 1, 0.1, 100);
    camera.position.set(0, 0.08, 3.45 / zoomRef.current);
    const isDarkGlobe = visualTheme === 'dark';
    let renderer: any;
    try {
      renderer = new WebGLRenderer({
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
    renderer.outputColorSpace = SRGBColorSpace;
    renderer.toneMapping = ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.06;
    renderer.setClearColor(isDarkGlobe ? 0x000000 : 0xf8fbff, 0);
    renderer.domElement.style.pointerEvents = 'auto';
    renderer.domElement.style.touchAction = 'none';
    host.appendChild(renderer.domElement);

    const tooltip = document.createElement('div');
    tooltip.className = 'globe-tooltip';
    tooltip.setAttribute('role', 'status');
    tooltip.setAttribute('aria-live', 'polite');
    tooltip.setAttribute('aria-atomic', 'true');
    host.appendChild(tooltip);

    const starField = createStarField(visualTheme);
    scene.add(starField);

    const earthGroup = new Group();
    const globeGeometry = new SphereGeometry(1, 112, 112);
    const cloudGeometry = new SphereGeometry(1.018, 96, 96);
    const atmosphereGeometry = new SphereGeometry(1.085, 96, 96);
    const cloudTexture = createCloudTexture();
    if (cloudTexture) {
      cloudTexture.wrapS = RepeatWrapping;
      cloudTexture.anisotropy = Math.min(4, renderer.capabilities.getMaxAnisotropy?.() ?? 1);
    }
    const gridSphere = createGridSphere(1.006, visualTheme);
    const globe = new Mesh(
      globeGeometry,
      new MeshPhysicalMaterial({
        map: null,
        roughness: isDarkGlobe ? 0.76 : 0.82,
        metalness: 0.02,
        clearcoat: isDarkGlobe ? 0.18 : 0.1,
        clearcoatRoughness: isDarkGlobe ? 0.58 : 0.7,
        emissive: new Color(isDarkGlobe ? 0x021b29 : 0xdff6fb),
        emissiveIntensity: isDarkGlobe ? 0.2 : 0.06,
      }),
    );
    earthGroup.add(globe);
    earthGroup.add(gridSphere);
    const globeMaterial = globe.material as any;

    const clouds = new Mesh(
      cloudGeometry,
      new MeshBasicMaterial({
        map: cloudTexture,
        transparent: true,
        opacity: isDarkGlobe ? 0.2 : 0.16,
        depthWrite: false,
        blending: AdditiveBlending,
      }),
    );
    earthGroup.add(clouds);

    const atmosphere = new Mesh(
      atmosphereGeometry,
      new ShaderMaterial({
        uniforms: {
          glowColor: { value: new Color(isDarkGlobe ? 0x5bdcff : 0x4e9ed1) },
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
        side: BackSide,
        depthWrite: false,
        blending: AdditiveBlending,
      }),
    );
    earthGroup.add(atmosphere);

    const markerGroup = new Group();
    earthGroup.add(markerGroup);
    earthGroup.rotation.y = -0.35;
    earthGroup.rotation.x = -0.08;
    scene.add(earthGroup);

    const fallbackTarget = { lat: 35.9, lon: 104.2, label: tRef.current('attackMap.protectedTarget'), source: 'fallback' as const };
    const runtime: GlobeRuntime = {
      renderer,
      scene,
      camera,
      tooltip,
      markerGroup,
      markerMeshes: [],
      regionObjects: new Map(),
      pulseRings: [],
      flowArcs: [],
      globeMaterial,
      worldTexture: null,
      protectedTarget: fallbackTarget,
      render: () => renderer.render(scene, camera),
    };
    runtimeRef.current = runtime;

    let controlsActive = false;
    let dragging = false;
    let lastPointerX = 0;
    let lastPointerY = 0;
    let rotationVelocityX = 0;
    let rotationVelocityY = 0;
    let cameraDistanceBase = 3.45;
    let cameraDistanceMultiplier = 1;
    let controlsIdleTimer = 0;
    const minDistance = 1.55;
    const maxDistance = 4.4;
    const rotateSpeed = isTouch ? 0.0062 : 0.0048;
    let requestFrame = () => {};
    const setControlsActive = (active: boolean) => {
      window.clearTimeout(controlsIdleTimer);
      if (active) {
        controlsActive = true;
        tooltip.classList.remove('globe-tooltip-visible');
        requestFrame();
        return;
      }
      controlsIdleTimer = window.setTimeout(() => {
        controlsActive = false;
      }, 120);
      requestFrame();
    };
    const updateCameraDistance = () => {
      camera.position.z = clamp(cameraDistanceBase * cameraDistanceMultiplier / Math.max(0.2, zoomRef.current), minDistance, maxDistance);
      camera.updateProjectionMatrix();
      runtime.render();
    };
    const applyRotationDelta = (dx: number, dy: number) => {
      rotationVelocityY = dx * rotateSpeed;
      rotationVelocityX = dy * rotateSpeed;
      earthGroup.rotation.y += rotationVelocityY;
      earthGroup.rotation.x = clamp(earthGroup.rotation.x + rotationVelocityX, -1.08, 1.08);
      requestFrame();
    };
    const onPointerDown = (event: globalThis.PointerEvent) => {
      if (event.button !== 0) {
        return;
      }
      dragging = true;
      lastPointerX = event.clientX;
      lastPointerY = event.clientY;
      setControlsActive(true);
      renderer.domElement.setPointerCapture?.(event.pointerId);
    };
    const onPointerUp = (event: globalThis.PointerEvent) => {
      if (!dragging) {
        return;
      }
      dragging = false;
      renderer.domElement.releasePointerCapture?.(event.pointerId);
      setControlsActive(false);
    };
    const onPointerCancel = (event: globalThis.PointerEvent) => {
      dragging = false;
      renderer.domElement.releasePointerCapture?.(event.pointerId);
      setControlsActive(false);
    };
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      setControlsActive(true);
      const zoomFactor = 1 + clamp(event.deltaY, -180, 180) * 0.0011;
      cameraDistanceMultiplier = clamp(cameraDistanceMultiplier * zoomFactor, 0.55, 1.72);
      updateCameraDistance();
      setControlsActive(false);
    };

    scene.add(new AmbientLight(isDarkGlobe ? 0x8fb7d9 : 0xffffff, isDarkGlobe ? 0.32 : 0.62));
    const hemi = new HemisphereLight(isDarkGlobe ? 0xa9e5ff : 0xf4fbff, isDarkGlobe ? 0x06101c : 0xb9d9e6, isDarkGlobe ? 0.82 : 0.9);
    scene.add(hemi);
    const light = new DirectionalLight(0xffffff, isDarkGlobe ? 2.35 : 1.78);
    light.position.set(3.4, 2.2, 4.2);
    scene.add(light);
    const rimLight = new DirectionalLight(isDarkGlobe ? 0x74e0ff : 0x3b8dbc, isDarkGlobe ? 1.15 : 0.48);
    rimLight.position.set(-3.4, 0.55, -2.3);
    scene.add(rimLight);

    const raycaster = new Raycaster();
    const pointer = new Vector2();
    let lastPointerRaycast = 0;
    const onPointerMove = (event: globalThis.PointerEvent) => {
      if (dragging) {
        event.preventDefault();
        const dx = event.clientX - lastPointerX;
        const dy = event.clientY - lastPointerY;
        lastPointerX = event.clientX;
        lastPointerY = event.clientY;
        applyRotationDelta(dx, dy);
        tooltip.classList.remove('globe-tooltip-visible');
        return;
      }
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
      const hit = raycaster.intersectObjects(runtime.markerMeshes, false)[0];
      if (!hit) {
        tooltip.classList.remove('globe-tooltip-visible');
        return;
      }
      const region = hit.object.userData.region as AttackRegion & { isTarget?: boolean };
      tooltip.textContent = region.isTarget
        ? `${runtime.protectedTarget.label} · ${tRef.current('attackMap.protectedTarget')}`
        : `${formatGlobeRegionLocation(region, tRef.current)} · ${region.attacks}`;
      tooltip.style.left = `${event.clientX - rect.left + 12}px`;
      tooltip.style.top = `${event.clientY - rect.top + 12}px`;
      tooltip.classList.add('globe-tooltip-visible');
    };
    const onPointerLeave = () => tooltip.classList.remove('globe-tooltip-visible');
    renderer.domElement.addEventListener('pointerdown', onPointerDown);
    renderer.domElement.addEventListener('pointermove', onPointerMove);
    renderer.domElement.addEventListener('pointerup', onPointerUp);
    renderer.domElement.addEventListener('pointercancel', onPointerCancel);
    renderer.domElement.addEventListener('pointerleave', onPointerLeave);
    renderer.domElement.addEventListener('wheel', onWheel, { passive: false });

    const resize = () => {
      const rect = host.getBoundingClientRect();
      const width = Math.max(320, rect.width);
      const height = Math.max(320, rect.height);
      const narrow = width < 560;
      const tallScreen = height >= 520 && height / Math.max(width, 1) > 0.72;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      // Keep the globe centered in tall attack-screen layouts (was drifting high).
      camera.position.y = tallScreen ? 0 : (narrow ? 0.04 : 0.06);
      cameraDistanceBase = tallScreen ? 3.05 : (narrow ? 3.75 : 3.35);
      updateCameraDistance();
      runtime.render();
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
    const stopFrame = () => {
      if (frame) {
        cancelAnimationFrame(frame);
        frame = 0;
      }
    };
    const tick = () => {
      frame = 0;
      const now = performance.now();
      if (hidden) {
        lastFrameAt = now;
        return;
      }
      const delta = Math.min((now - lastFrameAt) / 1000, 0.05);
      const elapsed = (now - startedAt) / 1000;
      lastFrameAt = now;
      if (!dragging) {
        earthGroup.rotation.y += rotationVelocityY;
        earthGroup.rotation.x = clamp(earthGroup.rotation.x + rotationVelocityX, -1.08, 1.08);
        rotationVelocityY *= reducedMotion ? 0.78 : 0.9;
        rotationVelocityX *= reducedMotion ? 0.78 : 0.9;
      }
      const shouldAutoRotate = !controlsActive && !dragging;
      if (!reducedMotion) {
        earthGroup.rotation.y += shouldAutoRotate ? delta * 0.038 : 0;
        clouds.rotation.y += delta * 0.024;
        clouds.rotation.x = Math.sin(elapsed * 0.12) * 0.012;
        starField.rotation.y += delta * 0.004;
        for (const item of runtime.pulseRings) {
          const wave = (Math.sin(elapsed * 2.4 + item.phase) + 1) / 2;
          item.mesh.scale.setScalar(1 + wave * 0.22);
          item.material.opacity = 0.28 + wave * 0.24;
        }
        for (const item of runtime.flowArcs) {
          const wave = (Math.sin(elapsed * 1.6 + item.phase) + 1) / 2;
          const progress = (elapsed * 0.16 + item.phase) % 1;
          item.material.opacity = 0.14 + wave * 0.24;
          item.head.position.copy(item.curve.getPoint(progress));
          item.headMaterial.opacity = 0.32 + Math.sin(progress * Math.PI) * 0.58;
        }
      }
      runtime.render();
      const hasInertia = Math.abs(rotationVelocityX) > 0.00008 || Math.abs(rotationVelocityY) > 0.00008;
      if (!reducedMotion || dragging || controlsActive || hasInertia) {
        requestFrame();
      }
    };
    requestFrame = () => {
      if (!frame && !hidden) {
        frame = requestAnimationFrame(tick);
      }
    };
    const updatePause = () => {
      hidden = document.visibilityState === 'hidden';
      reducedMotion = motionQuery.matches;
      if (hidden) {
        stopFrame();
        return;
      }
      lastFrameAt = performance.now();
      requestFrame();
    };
    document.addEventListener('visibilitychange', updatePause);
    motionQuery.addEventListener('change', updatePause);
    requestFrame();

    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener('visibilitychange', updatePause);
      motionQuery.removeEventListener('change', updatePause);
      observer.disconnect();
      window.clearTimeout(controlsIdleTimer);
      renderer.domElement.removeEventListener('pointerdown', onPointerDown);
      renderer.domElement.removeEventListener('pointermove', onPointerMove);
      renderer.domElement.removeEventListener('pointerup', onPointerUp);
      renderer.domElement.removeEventListener('pointercancel', onPointerCancel);
      renderer.domElement.removeEventListener('pointerleave', onPointerLeave);
      renderer.domElement.removeEventListener('wheel', onWheel);
      renderer.dispose();
      disposeObjectTree(starField, earthGroup);
      runtime.worldTexture?.dispose();
      cloudTexture?.dispose();
      if (resizeRef.current === resize) {
        resizeRef.current = null;
      }
      if (runtimeRef.current === runtime) {
        runtimeRef.current = null;
      }
      if (renderer.domElement.parentNode === host) {
        host.removeChild(renderer.domElement);
      }
      if (tooltip.parentNode === host) {
        host.removeChild(tooltip);
      }
    };
  }, [webglError, visualTheme]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime) {
      return;
    }
    updateGlobeTexture(runtime, countryLevelsRef.current, worldFeaturesRef.current, visualTheme);
  }, [countryLevelsSignature, worldSignature, visualTheme]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime) {
      return;
    }
    updateGlobeMarkerData(runtime, regionsRef.current, targetRef.current, tRef.current);
    rebuildGlobeMarkers(runtime, regionsRef.current, targetRef.current, tRef.current, visualTheme);
  }, [regionsSignature, targetSignature, t, visualTheme]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime) {
      return;
    }
    updateGlobeMarkerData(runtime, regions, target, t);
  }, [regions, target, t]);

  if (webglError) {
    return <>{fallback}</>;
  }

  return <div ref={hostRef} className={`globe-stage globe-stage-${visualTheme}`} role="img" aria-label={t('attackMap.title')} />;
}

function updateGlobeTexture(runtime: GlobeRuntime, countryLevels: Map<string, ThreatLevel>, worldFeatures: WorldFeature[], visualTheme: GlobeVisualTheme) {
  const texture = createWorldTexture(countryLevels, worldFeatures, visualTheme);
  if (texture) {
    texture.anisotropy = Math.min(8, runtime.renderer.capabilities.getMaxAnisotropy?.() ?? 1);
    texture.minFilter = LinearMipmapLinearFilter;
    texture.magFilter = LinearFilter;
  }
  runtime.worldTexture?.dispose();
  runtime.worldTexture = texture;
  runtime.globeMaterial.map = texture;
  runtime.globeMaterial.needsUpdate = true;
  runtime.render();
}

function rebuildGlobeMarkers(
  runtime: GlobeRuntime,
  regions: AttackRegion[],
  target: ProtectedTarget | undefined,
  t: (key: string, options?: Record<string, unknown>) => string,
  visualTheme: GlobeVisualTheme,
) {
  clearObjectGroup(runtime.markerGroup);
  runtime.markerMeshes.length = 0;
  runtime.regionObjects.clear();
  runtime.pulseRings.length = 0;
  runtime.flowArcs.length = 0;

  const isDarkGlobe = visualTheme === 'dark';
  const protectedTarget = target ?? { lat: 35.9, lon: 104.2, label: t('attackMap.protectedTarget'), source: 'fallback' as const };
  runtime.protectedTarget = protectedTarget;
  const protectedOrigin = latLonToVector(protectedTarget.lat, protectedTarget.lon, 1.052);
  const targetMarker = new Mesh(
    new SphereGeometry(0.024, 24, 24),
    new MeshBasicMaterial({
      color: isDarkGlobe ? 0xffffff : 0x0e7490,
      transparent: true,
      opacity: 0.96,
      depthWrite: false,
      blending: isDarkGlobe ? AdditiveBlending : NormalBlending,
    }),
  );
  targetMarker.position.copy(protectedOrigin);
  targetMarker.userData.region = { locationName: protectedTarget.label, attacks: t('attackMap.protectedTarget'), isTarget: true };
  runtime.markerMeshes.push(targetMarker);
  runtime.markerGroup.add(targetMarker);

  for (const [index, region] of regions.entries()) {
    const normal = latLonToVector(region.lat, region.lon, 1).normalize();
    const color = globeLevelColors[region.level] ?? markerColorFallback;
    const markerSize = Math.max(0.024, Math.min(0.076, region.size / 520));
    const height = Math.max(0.055, Math.min(0.18, region.size / 250));

    const ringMaterial = new MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.52,
      depthWrite: false,
      blending: AdditiveBlending,
    });
    const ring = new Mesh(new TorusGeometry(markerSize * 1.45, 0.0045, 10, 42), ringMaterial);
    ring.position.copy(normal.clone().multiplyScalar(1.041));
    orientNormal(ring, normal);
    ring.userData.region = region;

    const beamMaterial = new MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.7,
      depthWrite: false,
      blending: AdditiveBlending,
    });
    const beam = new Mesh(new CylinderGeometry(markerSize * 0.11, markerSize * 0.22, height, 16, 1, true), beamMaterial);
    beam.position.copy(normal.clone().multiplyScalar(1.052 + height / 2));
    beam.quaternion.setFromUnitVectors(new Vector3(0, 1, 0), normal);
    beam.userData.region = region;

    const tip = new Mesh(
      new SphereGeometry(1, 24, 24),
      new MeshBasicMaterial({ color, transparent: true, opacity: 0.98, blending: AdditiveBlending }),
    );
    tip.scale.setScalar(markerSize);
    tip.position.copy(normal.clone().multiplyScalar(1.072 + height));
    tip.userData.region = region;

    runtime.markerMeshes.push(ring, beam, tip);
    runtime.regionObjects.set(region.key, [ring, beam, tip]);
    runtime.pulseRings.push({ mesh: ring, material: ringMaterial, phase: index * 0.47 });
    runtime.markerGroup.add(ring, beam, tip);
    if (index < 48) {
      const arcMaterial = new MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.28,
        depthWrite: false,
        blending: AdditiveBlending,
      });
      const arc = createArcMesh(normal.clone().multiplyScalar(1.038), protectedOrigin, arcMaterial);
      const headMaterial = new MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.9,
        depthWrite: false,
        blending: AdditiveBlending,
      });
      const head = new Mesh(new SphereGeometry(0.014, 14, 14), headMaterial);
      head.position.copy(arc.curve.getPoint(0.12));
      runtime.markerGroup.add(arc);
      runtime.markerGroup.add(head);
      runtime.flowArcs.push({ material: arcMaterial, head, headMaterial, curve: arc.curve, phase: index * 0.31 });
    }
  }
  runtime.render();
}

function updateGlobeMarkerData(
  runtime: GlobeRuntime,
  regions: AttackRegion[],
  target: ProtectedTarget | undefined,
  t: (key: string, options?: Record<string, unknown>) => string,
) {
  const protectedTarget = target ?? { lat: 35.9, lon: 104.2, label: t('attackMap.protectedTarget'), source: 'fallback' as const };
  runtime.protectedTarget = protectedTarget;
  for (const mesh of runtime.markerMeshes) {
    if (mesh.userData.region?.isTarget) {
      mesh.userData.region = { locationName: protectedTarget.label, attacks: t('attackMap.protectedTarget'), isTarget: true };
    }
  }
  for (const region of regions) {
    const objects = runtime.regionObjects.get(region.key);
    if (!objects) {
      continue;
    }
    for (const object of objects) {
      object.userData.region = region;
    }
  }
}

function clearObjectGroup(group: any) {
  const children = [...group.children];
  for (const child of children) {
    group.remove(child);
    disposeObjectTree(child);
  }
}

function resolveGlobeTheme(theme: ThemeName): GlobeVisualTheme {
  return theme === 'dark' || theme === 'blackGold' ? 'dark' : 'light';
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function orientNormal(object: any, normal: any) {
  object.quaternion.setFromUnitVectors(new Vector3(0, 0, 1), normal);
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
  const curve = new CatmullRomCurve3([start, midpoint, end]);
  const mesh = new Mesh(new TubeGeometry(curve, 58, 0.0032, 8, false), material) as any;
  mesh.curve = curve;
  return mesh;
}

function createGridSphere(radius: number, visualTheme: GlobeVisualTheme) {
  const isDarkGlobe = visualTheme === 'dark';
  const group = new Group();
  const material = new LineBasicMaterial({
    color: isDarkGlobe ? 0x8ce8ff : 0x27799d,
    transparent: true,
    opacity: isDarkGlobe ? 0.16 : 0.11,
    depthWrite: false,
    blending: isDarkGlobe ? AdditiveBlending : NormalBlending,
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
  const geometry = new BufferGeometry().setFromPoints(points.map((point) => latLonToVector(point.lat, point.lon, radius)));
  return new Line(geometry, material);
}

function disposeObjectTree(...objects: any[]) {
  const geometries = new Set<any>();
  const materials = new Set<any>();
  objects.forEach((object) => {
    object.traverse((child: any) => {
      if (child.geometry instanceof BufferGeometry) {
        geometries.add(child.geometry);
      }
      const material = child.material;
      if (Array.isArray(material)) {
        material.forEach((item) => item instanceof Material && materials.add(item));
      } else if (material instanceof Material) {
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
  const geometry = new BufferGeometry();
  geometry.setAttribute('position', new BufferAttribute(positions, 3));
  return new Points(
    geometry,
    new PointsMaterial({
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
  return new Vector3(
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

  const texture = new CanvasTexture(canvas);
  texture.colorSpace = SRGBColorSpace;
  texture.wrapS = RepeatWrapping;
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
  const texture = new CanvasTexture(canvas);
  texture.colorSpace = SRGBColorSpace;
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
