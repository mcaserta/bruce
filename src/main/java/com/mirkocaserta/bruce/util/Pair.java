package com.mirkocaserta.bruce.util;

public final class Pair<K, V> {
  private final K key;
  private final V val;

  private Pair(K key, V val) {
    this.key = key;
    this.val = val;
  }

  public static <K, V> Pair<K, V> of(K key, V val) {
    return new Pair<>(key, val);
  }

  public static Pair<?, ?> empty() {
    return new Pair<>(null, null);
  }

  public boolean isEmpty() {
    return key == null && val == null;
  }

  public K key() {
    return key;
  }

  public V val() {
    return val;
  }
}
