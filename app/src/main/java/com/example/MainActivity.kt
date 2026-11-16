package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.EdgeTunnelRoot
import com.example.ui.viewmodel.MainViewModel

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    val appContainer = (application as EdgeTunnelApp).container
    setContent {
      val vm: MainViewModel = viewModel(factory = MainViewModel.Factory(appContainer))
      EdgeTunnelRoot(viewModel = vm)
    }
  }
}
