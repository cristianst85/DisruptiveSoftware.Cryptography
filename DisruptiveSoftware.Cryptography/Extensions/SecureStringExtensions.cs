using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace DisruptiveSoftware.Cryptography.Extensions
{
    public static class SecureStringExtensions
    {
        public static SecureString ToSecureString(this string str)
        {
            var secureString = new SecureString();

            foreach (char c in str)
            {
                secureString.AppendChar(c);
            }

            return secureString;
        }

        public unsafe static char[] ToCharArray(this SecureString secureString)
        {
            int length = secureString.Length;
            var insecureString = new string('\0', length);
            char[] result = null;

            var gcHandle = new GCHandle();

            RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(
                delegate
                {
                    RuntimeHelpers.PrepareConstrainedRegions();

                    try
                    {
                    }
                    finally
                    {
                        gcHandle = GCHandle.Alloc(insecureString, GCHandleType.Pinned);
                    }

                    IntPtr intPtr = IntPtr.Zero;

                    RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(
                        delegate
                        {
                            RuntimeHelpers.PrepareConstrainedRegions();

                            try
                            {
                            }
                            finally
                            {
                                intPtr = Marshal.SecureStringToBSTR(secureString);
                            }

                            var pString = (char*)intPtr;
                            var pInsecureString = (char*)gcHandle.AddrOfPinnedObject();

                            for (int index = 0; index < length; index++)
                            {
                                pInsecureString[index] = pString[index];
                            }
                        },
                        delegate
                        {
                            if (intPtr != IntPtr.Zero)
                            {
                                Marshal.ZeroFreeBSTR(intPtr);
                            }
                        },
                        null);

                    // Use the password.
                    result = insecureString.ToCharArray();
                },
                   delegate
                   {
                       if (gcHandle.IsAllocated)
                       {
                           // Zero the string.
                           var pInsecureString = (char*)gcHandle.AddrOfPinnedObject();

                           for (int index = 0; index < length; index++)
                           {
                               pInsecureString[index] = '\0';
                           }

                           gcHandle.Free();
                       }
                   },
                null);

            return result;
        }
    }
}
