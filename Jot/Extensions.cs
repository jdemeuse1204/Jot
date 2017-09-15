using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;

namespace Jot
{
    internal static class Extensions
    {
        public static bool IsNullable(this Type type)
        {
            return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>);
        }

        public static Type GetParameterType(this ParameterInfo parameter)
        {
            return IsNullable(parameter.ParameterType) ? Nullable.GetUnderlyingType(parameter.ParameterType) : parameter.ParameterType;
        }

        public static dynamic ConvertTo(this object value, Type type)
        {
            if (value.GetType() == type) return value;

            return (dynamic)TypeDescriptor.GetConverter(type).ConvertFrom(value.ToString());
        }

        public static dynamic ConvertTo<T>(this object value)
        {
           return ConvertTo(value, typeof(T));
        }

        public static List<T> GetCustomAttributes<T>(this MethodInfo methodInfo) where T : class
        {
            return methodInfo.GetCustomAttributes(false).Where(w => w.GetType() == typeof(T)).Cast<T>().ToList();
        }

        public static List<T> GetCustomAttributes<T>(this Type type) where T : class
        {
            return type.GetCustomAttributes(false).Where(w => w.GetType() == typeof(T)).Cast<T>().ToList();
        }

        public static T GetCustomAttribute<T>(this Type type) where T : class
        {
            var result = type.GetCustomAttributes(false).FirstOrDefault(w => w.GetType() == typeof(T));

            return result == null ? default(T) : (T)result;
        }

        public static bool HasAttribute<T>(this MethodInfo methodInfo) where T : class
        {
            return methodInfo.GetCustomAttributes(false).Any(w => w.GetType() == typeof(T));
        }

        public static T Invoke<T>(this MethodInfo method, object instance, object[] parameters)
        {
            return (T)method.Invoke(instance, null);
        }

        public static T InvokeAndMatchParameters<T>(this MethodInfo method, object instance, object[] parameters)
        {
            return (T)method.Invoke(instance, method.GetParameters().Select(w => GetValue(w.GetType(), parameters)).ToArray());
        }

        private static object GetValue(Type type, object[] parameters)
        {
            return parameters.First(w => w.GetType() == type);
        }

        public static void TryInvoke(this MethodInfo method, object instance, object[] parameters)
        {
            method?.Invoke(instance, parameters);
        }
    }
}
