// ::::    :::     ::: ::::::::::: :::::::::  ::::::::::: :::    :::   :::   ::: 
// :+:+:   :+:   :+: :+:   :+:     :+:    :+:     :+:     :+:    :+:  :+:+: :+:+: 
// :+:+:+  +:+  +:+   +:+  +:+     +:+    +:+     +:+     +:+    +:+ +:+ +:+:+ +:+ 
// +#+ +:+ +#+ +#++:++#++: +#+     +#++:++#:      +#+     +#+    +:+ +#+  +:+  +#+  
// +#+  +#+#+# +#+     +#+ +#+     +#+    +#+     +#+     +#+    +#+ +#+       +#+   
// #+#   #+#+# #+#     #+# #+#     #+#    #+#     #+#     #+#    #+# #+#       #+#    
// ###    #### ###     ### ###     ###    ### ###########  ########  ###       ###     

// NaHook
// Native hooking lib
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Natrium
{
    /// <summary>
    /// Class for managing hooks
    /// </summary>
    public static class NaHook
    {
        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtect(nint lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

        /// <summary>
        /// List of hooks.
        /// </summary>
        public static Dictionary<string, IHook> Hooks = new();

        /// <summary>
        /// Hook into a native function, replacing it with the hook. Returns Hook, which is used to unhook and contains crucial information like the original method.
        /// </summary>
        /// <param name="NativeFunction">Function pointer for function to hook</param>
        /// <param name="hook">Delegate of the hook</param>
        /// <param name="Identifier">Key for the entry in Hooks dictionary</param>
        /// <returns>Object representing hook</returns>
        public static Hook<T> Hook<T>(IntPtr NativeFunction, T hook, string Identifier, bool AddToDict = true)
        {
            IntPtr HookPointer = Marshal.GetFunctionPointerForDelegate(hook);
            return new(HookPointer, hook, GetBytes(NativeFunction,5), Identifier);
        }

        public static unsafe byte[] GetBytes(IntPtr NativeFunction, int x)
        {
            List<byte> LOriginalBytes = new();
            byte[] OriginalBytes;
            byte* p = (byte*)NativeFunction.ToPointer();
            for (int i = 0; i < 5; i++)
            {
                LOriginalBytes.Add(p[x]);
            }
            return LOriginalBytes.ToArray();
        }
    }

    /// <summary>
    /// Interface of Hook<T> when you need to use the Hook object and dont know the type beforehand
    /// </summary>
    public interface IHook
    {
        void Rehook();
        void Unhook();
        void UnhookPerma();
    }

    /// <summary>
    /// Instance of a hook.
    /// </summary>
    /// <typeparam name="T">Delegate type.</typeparam>
    public class Hook<T> : IHook
    {
        public IntPtr JmpLocation;
        public T HookFnc;
        public byte[] OriginalFnc;
        public string Identifier;

        public bool Hooked;

        public Hook(IntPtr jl, T hf, byte[] of, string identifier)
        {
            (JmpLocation, HookFnc, OriginalFnc, Identifier) = (jl, hf, of, identifier);
            Rehook();
            if (NaHook.Hooks.ContainsKey(Identifier))
                NaHook.Hooks[Identifier].UnhookPerma();
            NaHook.Hooks.Add(Identifier, this);
        }

        /// <summary>
        /// Readd the previously removed hook
        /// </summary>
        /// <exception cref="System.ComponentModel.Win32Exception">Unknown windows error</exception>
        public unsafe void Rehook()
        {
            if (Hooked)
                throw new Exception("Already hooked");
            uint OldProtect;
            List<byte> LOriginalBytes = new();
            IntPtr HookPointer = Marshal.GetFunctionPointerForDelegate(HookFnc);
            if (NaHook.VirtualProtect(JmpLocation, (UIntPtr)5, 0x40, out OldProtect))
            {
                byte* p = (byte*)JmpLocation.ToPointer();

                // Store the original bytes
                for (int i = 0; i < 5; i++)
                {
                    LOriginalBytes.Add(p[i]);
                }
                OriginalFnc = LOriginalBytes.ToArray();

                *p = 0xE9; // JMP
                *(int*)(p + 1) = (int)(HookPointer.ToInt64() - JmpLocation.ToInt64() - 5);
                NaHook.VirtualProtect(JmpLocation, (UIntPtr)5, OldProtect, out _);
                Hooked = true;
            }
            else
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        /// <summary>
        /// Remove the hook and restore the bytes
        /// </summary>
        /// <exception cref="System.ComponentModel.Win32Exception">Unknown windows error</exception>
        public unsafe void Unhook()
        {
            if (!Hooked)
                throw new Exception("Already unhooked");
            uint oldProtect;
            if (NaHook.VirtualProtect(JmpLocation, (UIntPtr)5, 0x40, out oldProtect))
            {
                byte* p = (byte*)JmpLocation.ToPointer();
                for (int i = 0; i < 5; i++)
                {
                    p[i] = OriginalFnc[i];
                }
                NaHook.VirtualProtect(JmpLocation, (UIntPtr)5, oldProtect, out _);
                Hooked = false;
            }
            else
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        /// <summary>
        /// Unhooks and removes from the Hooks dict.
        /// </summary>
        public unsafe void UnhookPerma()
        {
            Unhook();
            NaHook.Hooks.Remove(Identifier);
        }
    }
}
