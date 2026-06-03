<template>
  <div>
    <p class="font-weight-bold text-right"> {{ formattedCountdown }} </p>
  </div>
</template>

<script>
export default {
  name: 'Countdown',
  props: {
    name: { type: String, required: true }, // เช่น 'mfu-home'
    size: { type: String, default: 'md' }
  },
  data () {
    return {
      targetTime: new Date('2025-07-15T23:59:59'),
      now: new Date(),
      timer: null
    }
  },
  computed: {
    formattedCountdown() {
      const diff = Math.max(0, this.targetTime - this.now);
      const seconds = Math.floor((diff / 1000) % 60);
      const minutes = Math.floor((diff / (1000 * 60)) % 60);
      const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      return `${days}d ${hours}h ${minutes}m ${seconds}s`;
    }
  },
  mounted() {
    this.timer = setInterval(() => {
      this.now = new Date();
    }, 1000);
  },
  beforeUnmount() {
    clearInterval(this.timer);
  }
}
</script>
