using System;
using System.Runtime.InteropServices;

class MonoJitExample {
    public static void Main(string[] args) {
        var library_path = args[0];

        Console.WriteLine("Loading library from: " + library_path);

        unsafe {
            /* NOTE: Proper error handling and an implementation on */ 
            /* Windows is an exercise for the reader.               */
            var library = dlopen(library_path, 2);
            var emit_length = (delegate*<object,                IntPtr>) dlsym(library, "emit_length");
            var emit =        (delegate*<object,                IntPtr>) dlsym(library, "emit");
            var invoke =      (delegate*<IntPtr, object, byte*, nuint>)  dlsym(library, "invoke");
            var destroy =     (delegate*<IntPtr,                void>)   dlsym(library, "destroy");

            /* Create random instance of the target object. */
            var obj = new Vector3(-0.108f, 0.082f, 0.215f);

            /* Construct length and serialization buffer. */
            var length_buffer = emit_length(obj);
            var serialize_buffer = emit(obj);

            /* Mutate your target object however you like or */
            /* create new instances.                         */

            /* Get length of the output string to ensure buffer size.    */
            /* If you are absolutely sure, that your object won't excede */
            /* your already allocated buffer size, you can omit this.    */
            var length = invoke(length_buffer, obj, null);
            var buffer = new byte[length];

            /* Actually serialize object. */
            fixed (byte* b = buffer) {
                var actual_length = invoke(serialize_buffer, obj, b);

                System.Diagnostics.Debug.Equals(length, actual_length);
            }

            /* NOTE: */
            /* Instead of reading the string into the UTF-16 .NET domain, */
            /* you should pass it to your library that requires UTF-8.    */
            var str = System.Text.Encoding.UTF8.GetString(buffer);
            Console.WriteLine(str);

            /* Destroy execution buffers. */
            destroy(serialize_buffer);
            destroy(length_buffer);

            dlclose(library);
        }
    }

    [DllImport("libdl.so.2")]
    static extern IntPtr dlopen(string filename, int flags);

    [DllImport("libdl.so.2")]
    static extern IntPtr dlclose(IntPtr handle);
    
    [DllImport("libdl.so.2")]
    static extern IntPtr dlsym(IntPtr handle, string symbol);
    
    [DllImport("libdl.so.2")]
    static extern string dlerror();
}
