tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
      colors: {
        ink: {
          950: '#0e1621', 900: '#17212b', 850: '#1c2733', 800: '#202b36',
          700: '#2b3844', 600: '#3a4a5c', 500: '#5a6b7d', 400: '#8b98a5', 200: '#e6ebf0',
        },
        brand: {
          400: '#62a8f0', 500: '#3390ec', 600: '#1c7ad6', 700: '#155fa8',
        },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(51,144,236,.35), 0 10px 30px -10px rgba(51,144,236,.5)',
      }
    }
  }
}