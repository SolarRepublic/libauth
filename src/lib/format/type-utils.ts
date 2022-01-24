export type PartialExactOptional<T> = {
  [P in keyof T]?: T[P] | undefined;
};

type ImmutablePrimitive =
  // eslint-disable-next-line @typescript-eslint/ban-types
  Function | boolean | number | string | null | undefined;
type ImmutableArray<T> = readonly Immutable<T>[];
type ImmutableMap<K, V> = ReadonlyMap<Immutable<K>, Immutable<V>>;
type ImmutableSet<T> = ReadonlySet<Immutable<T>>;
type ImmutableObject<T> = {
  readonly [K in keyof T]: Immutable<T[K]>;
};
type ImmutableUint8Array = ImmutableObject<Uint8Array> &
  Iterable<number> &
  Readonly<ArrayLike<number>>;

/**
 * A deep-readonly utility type. Can be removed when a built-in alternative is
 * added to TypeScript. Derived from:
 * https://github.com/microsoft/TypeScript/issues/13923#issuecomment-557509399
 */
export type Immutable<T> = T extends ImmutablePrimitive
  ? T
  : T extends (infer U)[]
  ? ImmutableArray<U>
  : T extends Map<infer K, infer V>
  ? ImmutableMap<K, V>
  : T extends Set<infer M>
  ? ImmutableSet<M>
  : T extends Uint8Array
  ? ImmutableUint8Array
  : ImmutableObject<T>;

/*
 * const canBeAssigned: Immutable<Uint8Array> = Uint8Array.of(0, 0);
 * const canBeSpread = [...canBeAssigned];
 * const spreadResultWorks = Uint8Array.from(canBeSpread);
 * const functionRequiringIt = (bin: Immutable<Uint8Array>) => bin;
 * const canAcceptNonMutable = functionRequiringIt(Uint8Array.of());
 */

// TODO: use or remove
