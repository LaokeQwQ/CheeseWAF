declare module '@province-city-china/province/province.json' {
  const value: Array<{ code: string; name: string; province: string }>;
  export default value;
}

declare module '@province-city-china/city/city.json' {
  const value: Array<{ code: string; name: string; province: string; city: string }>;
  export default value;
}

declare module '@province-city-china/area/area.json' {
  const value: Array<{ code: string; name: string; province: string; city: string; area: string }>;
  export default value;
}
