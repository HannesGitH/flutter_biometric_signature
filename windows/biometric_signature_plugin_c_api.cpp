#include "include/biometric_signature/biometric_signature_plugin_c_api.h"
#include "include/biometric_signature/biometric_signature_plugin.h"

#include <flutter/plugin_registrar_windows.h>

#include "biometric_signature_plugin.h"

void BiometricSignaturePluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  biometric_signature::BiometricSignaturePlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}

void BiometricSignaturePluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  biometric_signature::BiometricSignaturePlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
