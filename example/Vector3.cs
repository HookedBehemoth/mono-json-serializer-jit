using System;
using System.Runtime.CompilerServices;

public struct Vector3
{
    // *Undocumented*
    public const float kEpsilon = 0.00001F;
    // *undoc* --- there's a property now
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Magnitude(Vector3 vector) { return (float)Math.Sqrt(vector.x * vector.x + vector.y * vector.y + vector.z * vector.z); }

    // *undoc* --- we have normalized property now
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector3 Normalize(Vector3 value)
    {
        float mag = Magnitude(value);
        if (mag > kEpsilon)
            return value / mag;
        else
            return zero;
    }
    // Returns this vector with a ::ref::magnitude of 1 (RO).
    public Vector3 normalized
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get { return Vector3.Normalize(this); }
    }
    static readonly Vector3 zeroVector = new Vector3(0F, 0F, 0F);
    // Shorthand for writing @@Vector3(0, 0, 0)@@
    public static Vector3 zero { [MethodImpl(MethodImplOptions.AggressiveInlining)] get { return zeroVector; } }
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector3 operator /(Vector3 a, float d) { return new Vector3(a.x / d, a.y / d, a.z / d); }
    public Vector3(float _x, float _y, float _z)
    {
        x = _x; y = _y; z = _z;
    }
    public float x, y, z;
};
