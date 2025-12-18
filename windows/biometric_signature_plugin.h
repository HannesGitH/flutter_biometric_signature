#ifndef FLUTTER_PLUGIN_BIOMETRIC_SIGNATURE_PLUGIN_H_
#define FLUTTER_PLUGIN_BIOMETRIC_SIGNATURE_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <string>

namespace biometric_signature {

class BiometricSignaturePlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  BiometricSignaturePlugin();

  virtual ~BiometricSignaturePlugin();

  // Disallow copy and assign.
  BiometricSignaturePlugin(const BiometricSignaturePlugin&) = delete;
  BiometricSignaturePlugin& operator=(const BiometricSignaturePlugin&) = delete;

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  // Handler methods for each API function
  void HandleBiometricAuthAvailable(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleCreateKeys(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleCreateSignature(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleDeleteKeys(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleGetKeyInfo(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleDecrypt(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace biometric_signature

#endif  // FLUTTER_PLUGIN_BIOMETRIC_SIGNATURE_PLUGIN_H_
