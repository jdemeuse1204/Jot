using Jot.Attributes;
using Jot.Time;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Jot
{
    internal class JotCreationHelper
    {
        public static List<ParameterInfo> GetUndecoratedParameters(List<ParameterInfo> parametersToFilter)
        {
            return parametersToFilter.Where(w => w.GetCustomAttributes(false).All(x => x.GetType() != typeof(InjectAdditionalClaim) && x.GetType() != typeof(InjectFromPayload))).ToList();
        }

        public static List<ParameterInfo> GetInjectableItemAttributes(List<ParameterInfo> parametersToFilter)
        {
            return parametersToFilter.Where(w => w.GetCustomAttributes(false).Any(x => x.GetType() == typeof(InjectAdditionalClaim) || x.GetType() == typeof(InjectFromPayload))).ToList();
        }

        public static bool UseAnonymousHeader<T>() where T : class
        {
            return typeof(T).GetCustomAttribute<AnonymouseAlgorithmInHeader>() != null;
        }

        public static int GetJwtTimeout<T>() where T : class
        {
            var attribute = typeof(T).GetCustomAttribute<TokenTimeout>();

            if (attribute == null)
            {
                throw new JotException($"Cannot find TokenTimeout attribute on class {typeof(T).Name}.  {typeof(T).Name} must be decorated with TokenTimeout attribute.");
            }

            return attribute.Timeout;
        }

        public static string GetSecret<T>(object instance) where T : class
        {
            var method = GetMethodWithParameters<T, OnGetSecret, string>(0);

            if (method == null)
            {
                throw new JotException($"Cannot find OnGetSecret method for class {typeof(T).Name}.  {typeof(T).Name} must have method decorated with OnGetSecret attribute, have no parameters and return a string.");
            }

            return method.Invoke<string>(instance, null);
        }

        public static IUnixTimeProvider GetOnGetUnixTimeProvider<T>(object instance) where T : class
        {
            if (!ClassCotnainsMethodWithAttribute<T, OnGetUnixTimeStamp>()) { return null; }

            var method = GetMethodWithParameters<T, OnGetUnixTimeStamp, IUnixTimeProvider>(0);

            if (method == null)
            {
                throw new JotException($"OnGetUnixTimeStamp method malformed for class {typeof(T).Name}.  Method must be decorated with OnGetUnixTimeStamp attribute, have no parameters and return IUnixTimeProvider.");
            }

            return method.Invoke<IUnixTimeProvider>(instance, null);
        }

        public static HashAlgorithm? GetHashAlgorithm<T>() where T : class
        {
            var value = typeof(T).GetCustomAttribute<HashAlgorithmType>();

            return value == null ? null : (HashAlgorithm?)value.HashAlgorithm;
        }

        public static MethodInfo GetOnDeserializeMethod<T>() where T : class
        {
            if (!ClassCotnainsMethodWithAttribute<T, OnDeserialize>()) { return null; }// no error, this is optional

            var method = GetMethodWithParameters<T, OnDeserialize, Dictionary<string, object>>(1);

            if (method == null)
            {
                throw new JotException($"OnDeserialize method malformed for class {typeof(T).Name} must take in one parameter of type string and return Dictionary<string, object>.");
            }

            var parameters = method.GetParameters().ToList();

            if (parameters.Count != 1 || parameters[0].ParameterType != typeof(string))
            {
                throw new JotException($"OnDeserialize method malformed for class {typeof(T).Name} must take in one parameter of type string.");
            }

            return method;
        }

        public static MethodInfo GetOnSerializeMethod<T>() where T : class
        {
            if (!ClassCotnainsMethodWithAttribute<T, OnSerialize>()) { return null; }// no error, this is optional

            var method = GetMethodWithParameters<T, OnSerialize, string>(1);

            if (method == null)
            {
                throw new JotException($"OnSerialize method malformed for class {typeof(T).Name} must take in one parameter of type object and return string.");
            }

            var parameters = method.GetParameters().ToList();

            if (parameters.Count != 1 || parameters[0].ParameterType != typeof(object))
            {
                throw new JotException($"OnSerialize method malformed for class {typeof(T).Name} must take in one parameter of type object.");
            }

            return method;
        }

        public static bool IsUsingGhostClaims<T>() where T : class
        {
            return ClassCotnainsMethodWithAttribute<T, OnGetGhostClaims>();
        }

        public static MethodInfo GetOnGetGhostClaims<T>() where T : class
        {
            if (!ClassCotnainsMethodWithAttribute<T, OnGetGhostClaims>()) { return null; }// no error, this is optional

            var method = GetMethodWithParameters<T, OnGetGhostClaims, Dictionary<string, object>>(0);

            if (method == null)
            {
                throw new JotException($"OnGetGhostClaims method malformed for class {typeof(T).Name} must take in no parameters and return Dictionary<string, object>.");
            }

            var parameters = method.GetParameters().ToList();

            if (parameters.Count != 0)
            {
                throw new JotException($"OnGetGhostClaims method malformed for class {typeof(T).Name} must take in no parameters.");
            }

            return method;
        }

        public static bool HasOnHashMethod<T>() where T : class
        {
            return ClassCotnainsMethodWithAttribute<T, OnHash>();
        }

        public static MethodInfo GetOnHashMethod<T>() where T : class
        {
            if (!ClassCotnainsMethodWithAttribute<T, OnHash>()) { return null; }// no error, this is optional

            var method = GetMethodWithParameters<T, OnHash, byte[]>(2);

            if (method == null)
            {
                throw new JotException($"OnHash method malformed for class {typeof(T).Name} must take in two parameters of type byte[] and string in any order and return byte[].");
            } 

            var parameter = method.GetParameters().ToList();

            if (!parameter.Any(w => w.ParameterType == typeof(byte[])) || !parameter.Any(w => w.ParameterType == typeof(string)))
            {
                throw new JotException($"OnHash method malformed for class {typeof(T).Name} must take in two parameters of type byte[] and string in any order.");
            }

            return method;
        }

        public static MethodInfo GetOnCreateMethod<T>() where T : class
        {
            if (!ClassCotnainsMethodWithAttribute<T, OnCreate>()) { return null; }

            var method = GetMethodWithParametersAndNoReturnType<T, OnCreate>(1);

            if (method == null)
            {
                throw new JotException($"OnCreate method malformed for class {typeof(T).Name}.  Method must be decorated with OnCreate attribute, take in an IJotToken and be a void.");
            }

            var parameter = method.GetParameters().First();

            if (parameter.ParameterType != typeof(IJotToken))
            {
                throw new JotException($"OnCreate method malformed for class {typeof(T).Name} must take in parameter of type IJotToken, but instead takes in type of {parameter.ParameterType.Name}.");
            }

            return method;
        }

        public static bool ClassCotnainsMethodWithAttribute<T, K>() where T : class where K : class
        {
            return typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public).Any(w => w.HasAttribute<K>());
        }

        /// <summary>
        /// Get a method that has no parameters
        /// </summary>
        /// <typeparam name="T">Attribute Type</typeparam>
        /// <typeparam name="K">Return Signature Type</typeparam>
        /// <returns></returns>
        private static MethodInfo GetMethodWithParameters<T, K, Y>(int parameterCount) where T : class where K : class
        {
            return typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public).FirstOrDefault(w => w.HasAttribute<K>() && w.ReturnType == typeof(Y) && w.GetParameters().Count() == parameterCount);
        }

        /// <summary>
        /// Get a method that has no parameters
        /// </summary>
        /// <typeparam name="T">Attribute Type</typeparam>
        /// <typeparam name="K">Return Signature Type</typeparam>
        /// <returns></returns>
        private static MethodInfo GetMethodWithParametersAndNoReturnType<T, K>(int parameterCount) where T : class where K : class
        {
            return typeof(T).GetMethods(BindingFlags.Instance | BindingFlags.Public).FirstOrDefault(w => w.HasAttribute<K>() && w.GetParameters().Count() == parameterCount);
        }
    }
}
